# `espclient.dll` and WESP security review

## Executive result

No confirmed kernel memory-corruption vulnerability or production authorization bypass was found in this static review. The driver-facing boundary is unusually defensive: restricted Filter Manager port ACL, token permission/PPL checks, per-message capability verification, a fixed 64-byte envelope, probing and bounded copies of nested user memory, checked arithmetic, alignment checks, discriminant validation, and Rust ownership on both sides.

The review did identify three concrete user-mode robustness defects and several high-value security hypotheses that require Windows runtime testing. The most security-relevant attack surface is not ordinary unprivileged access; it is an authorized or test-signing-relaxed consumer using WESP's broad cross-client management and policy APIs, plus any bug in the complex nested rule/property parsers.

Severity below assumes the attacker starts without WESP permission. Findings that only crash the caller are rated Low even when reliable.

## Confirmed findings

### EC-01: callback-initiated queue disconnect deadlocks and eventually fail-fasts

**Severity:** Low — local consumer denial of service  
**Confidence:** High, direct control-flow evidence  
**Functions:** `PortListener::ThreadPoolCallback` `0x1800dcf10`, `PortListener::CompleteDisconnect` `0x1800dd1c0`, `EventQueue::Disconnect` `0x1800de780`

The thread-pool callback increments the listener's pending-I/O count before delivery and only decrements it after the user callback returns. If the user callback synchronously calls `EspDisconnectEventQueue`, disconnect waits for that same pending count to reach zero. The callback cannot return to decrement it because it is blocked inside disconnect. After 300,000 ms, `CompleteDisconnect` calls WIL's unexpected-condition fail-fast.

This is a reliable self-deadlock/process termination in an otherwise plausible API usage pattern. It does not cross a privilege boundary, but an event-controlled callback path can turn it into an availability issue in a security product.

**Mitigation:** document that teardown must be scheduled onto another thread after the callback returns. The library should detect callback-thread reentrancy and return an error, or split begin-disconnect from the blocking join.

**Runtime test:** connect a queue in callback mode; on the first event, call `EspDisconnectEventQueue` from the callback. Confirm the five-minute wait and fail-fast under Application Verifier/WinDbg.

### EC-02: registration performs unbounded reads of caller UTF-16 strings

**Severity:** Low — local consumer crash/read amplification  
**Confidence:** High  
**Functions:** `EspRegisterClient` `0x1800d65e0`, `ClientObject::Register` `0x1800dadb0`

The API accepts two nullable string pointers with no lengths. It scans each two bytes at a time until a NUL terminator, without structured exception handling or a maximum. An invalid pointer or unterminated readable region causes an access violation or an extremely long scan/allocation attempt.

The resulting byte lengths are stored in 16-bit fields. Strings larger than the representable protocol length are narrowed without an explicit public-side rejection. The driver should reject the inconsistent context, so this is not evidence of kernel corruption, but it creates avoidable truncation/version-desynchronization behavior.

**Mitigation:** use bounded `wcsnlen`, reject odd/oversized byte lengths before allocation, and cap both strings to the driver protocol maximum.

### EC-03: failed IOCP delivery loses notification ownership/state

**Severity:** Low to Medium — notification loss, queue stall, or resource retention  
**Confidence:** Medium-high statically; impact needs runtime confirmation  
**Function:** `EventQueue::NotificationCallback` `0x1800ddab0` / `0x1800ddbe0`

In IOCP mode, after payload allocation and notification initialization, the library calls `PostQueuedCompletionStatus`. On failure it only logs `GetLastError` and returns. It does not complete the kernel notification, free the out-of-line payload, re-arm the buffer, or surface an error to the consumer. Because the consumer receives no completion, normal ownership recovery is unclear.

Closing or invalidating the IOCP handle at the delivery boundary can therefore strand a notification. Depending on kernel queue accounting, the result may be one lost buffer, retained payload memory, an in-flight slot that never completes, or queue backpressure.

**Mitigation:** on post failure, atomically mark the notification failed, complete/cancel it with the driver, release payload ownership, and expose an asynchronous error path.

**Runtime test:** race IOCP closure against high-rate events while tracking private bytes, queue state, in-flight count, and subsequent delivery.

## Defensive behavior confirmed

- `\\EspFilterPort` uses the Filter Manager default all-access descriptor, limiting opens to administrators and SYSTEM before WESP-specific checks.
- Connection setup accepts only kinds `0..6` and checks minimum lengths, alignment, counted strings, flags, token attributes, and process protection/test-signing state.
- `WESP://Permission` must have the expected security-attribute type and value shape.
- A capability tier is stored on the connection; `ClientMessage::verify_capabilities` reads it under a push lock before dispatch.
- The message callback probes the complete outer input/output and wraps them in bounded user-buffer objects.
- Nested pointers are copied through `copy_user_memory` and range-checked helpers. The fixed outer request is `0x40` bytes.
- The parser validates request IDs, enum ranges, flags, counts, alignment, multiplication/addition overflow, and output capacities.
- Notification pointer relocation rejects overflow, overlap with relocation metadata, misalignment, invalid property types, and cross-buffer out-of-range pointers.
- The DLL is compiled with ASLR, NX, CFG, CET, EH continuation metadata, and `/GS`.

These controls make parser fuzzing more valuable than superficial malformed-handle testing: a useful kernel finding must pass several independent layers.

## Security-relevant design risks and hypotheses

### EH-01: test-signing mode intentionally lowers the connection barrier

**Priority:** High for lab validation; Informational as a production vulnerability  
**Status:** Design behavior, independently runtime-observed on another build

Connection setup contains a fallback involving Code Integrity/test-signing state and process protection when the expected token permission is absent or insufficient. Independent runtime research reports that an elevated administrator could connect on a test-signed preview system without the normal token attribute, while the stronger permission tier required Antimalware PPL when test signing was off.

This is an excellent supported research path and a dangerous deployment configuration. It is not, by itself, an elevation from an unprivileged production process.

**Test:** build a matrix of standard user/admin/SYSTEM/PPL and test-signing on/off against all seven connection kinds and all 29 request IDs. Record exact NTSTATUS/HRESULT values for this exact version.

### EH-02: cross-client administrative operations may enable security-product tampering

**Priority:** High  
**Status:** Capability/authorization test required

The public API can enumerate registered and connected client GUIDs, query arbitrary client descriptors, unregister a GUID, and connect to a supplied GUID. Once connected, it can remove or replace rules and clear or close queues. The connection context does not carry an additional user-mode proof of ownership; enforcement is therefore entirely in the driver permission tier and stored client metadata.

Questions to answer dynamically:

1. Can a caller with the lower WESP permission value enumerate or query a different vendor's client?
2. Can either tier unregister, connect to, mutate rules for, or clear queues belonging to another signer/product?
3. Are persisted clients bound to a signer, PPL signer level, service SID, image identity, or only a GUID plus permission tier?
4. Does a reconnect after process-protection downgrade retain access through an already-open port?

If the lower tier can mutate another product's state, this becomes a meaningful defense-evasion primitive. Static analysis confirms the primitives but not the missing policy check, so this is not reported as a vulnerability yet.

### EH-03: authorization is connection-scoped and not visibly re-derived on every message

**Priority:** Medium  
**Status:** Design/TOCTOU hypothesis

The expensive token security-attribute and PPL checks occur at connect. Per-message verification reads the capability cached in the connection. Test whether permission removal, token replacement, protection-level change, service restart, or client unregistration invalidates existing ports. Stale authorization may be intentional handle semantics, but it matters for privileged broker designs and revocation expectations.

### EH-04: nested rule and property graphs remain the prime kernel fuzzing surface

**Priority:** High  
**Status:** No flaw confirmed

Rule updates contain user pointers to arrays and deep tagged graphs representing many event families and object/property filters. The driver uses checked probes and Rust parsing, but this is the highest-complexity attacker-controlled input. Focus on:

- count × element-size overflow and zero-sized edge cases;
- pointer ranges that touch but do not overlap;
- misalignment at 2/4/8-byte boundaries;
- duplicated/cyclic filter subgraphs and extreme depth;
- mismatched union discriminants and descriptor sizes;
- collection updates whose strings/arrays alias the outer request or output;
- output length changes between sizing and copy calls;
- cancellation/disconnect during copy and rule commit;
- persistence/recovery of partially committed updates.

A fuzzer should generate through the public DLL first, then mutate the serialized 64-byte message and nested buffers immediately before `FilterSendMessage`. The first mode tests supported input; the second tests driver validation gaps.

### EH-05: notification state-machine races

**Priority:** High  
**Status:** Runtime test required

Exercise concurrent `Arm`, `Complete`, `Clear`, queue close, queue disconnect, state-listener removal, client disconnect, and buffer free. Particularly useful sequences are:

- complete the same notification twice;
- free while armed or during callback;
- arm one buffer on two queues;
- complete after disconnect/reconnect;
- clear while payload request `0x1c` is in flight;
- close the queue or client from callback/IOCP consumer threads;
- reuse a buffer after a failed payload fetch or failed IOCP post.

The DLL has locks and states for normal use, but opaque public pointers and callback reentrancy make misuse paths easy to reach. Kernel impact is not demonstrated.

### EH-06: malformed trusted-driver responses cause client fail-fast

**Priority:** Medium  
**Status:** Confirmed behavior; exploit requires a buggy/compromised/mismatched kernel peer

The Rust transport treats impossible success responses as process invariants. Examples include a fixed response with the wrong byte count or a returned length larger than the supplied output capacity. These call `FUN_1800e01b0`/WIL fail-fast rather than returning an HRESULT.

This is reasonable across a trusted in-box version pair, but it magnifies version skew and any kernel response corruption into deterministic termination of the security consumer.

## API misuse hazards

Public handles are user-mode pointers to shared C++ wrapper objects, not kernel handles with type enforcement. Most exports check null but cannot safely distinguish a stale, forged, freed, or cross-type pointer. Misuse can produce an access violation, use-after-free, wrong-object method call, or arbitrary delete inside the caller's own process. This does not improve an attacker's position once they already control that process, but consumers should wrap handles in strict RAII types and serialize teardown.

Other hazards:

- `EspFreeMemory` and the close/free functions require the correct allocator/handle family.
- Callback context pointers are raw and must outlive all pending callbacks.
- Notification buffers have a multi-stage ownership contract; completing is distinct from freeing and re-arming.
- Queue/state callbacks can run concurrently on a configurable thread pool.
- Event descriptors and filter values often contain borrowed pointers that must remain valid through serialization.
- Calling raw internal `EspRs*` routines by RVA is unsafe across versions.

## Offsec-relevant capabilities

With a legitimately authorized connection—or in a deliberately test-signed lab—the following capabilities are useful for adversary simulation and defensive testing:

| Capability | Use |
|---|---|
| Enumerate registered/connected client GUIDs | Discover WESP-backed security products and active consumers |
| Query client descriptor | Fingerprint name, altitude, version-specific configuration |
| Connect/unregister a client | Test cross-client isolation and tamper resistance |
| Enumerate/remove/update rules | Audit or attempt policy weakening; test persistence/recovery |
| Create/open/update collections | Supply high-volume rule data and stress persistence/parsing |
| Create/open/clear/close queues | Test telemetry suppression and queue-accounting boundaries |
| Subscribe to events | Build system-wide telemetry prototypes without a custom driver |
| Reference process/thread/token/file/registry/etc. | Resolve object properties and exercise lifetime races |
| Set client/object context keys | Test typed state propagation and parser edge cases |
| Query property support/capabilities | Discover version-specific attack surface before fuzzing |

Do not describe these as an unprivileged bypass: the production gate is the central question.

## Recommended test harnesses

1. **Capability matrix:** attempt every connection kind and request ID under controlled token/PPL/test-signing combinations.
2. **Public ABI exerciser:** dynamically load all 120 exports, test null/boundary inputs, and verify HRESULT plus ETW behavior.
3. **Rule grammar fuzzer:** construct valid graphs through exports, serialize, then mutate counts, tags, nesting, pointers, and lifetimes.
4. **Queue race harness:** high-rate events with randomized arm/complete/clear/disconnect/close/free sequences.
5. **Cross-client isolation suite:** two registered GUIDs under distinct processes/signers; attempt every management operation across them.
6. **Persistence/recovery suite:** reboot or restart at each update commit point and validate fail-closed behavior.
7. **Version-skew suite:** deliberately mismatch nearby DLL/driver builds and record fail-fast versus clean rejection.

Use a disposable VM with kernel debugging, Driver Verifier scoped to `wesp.sys`, full dumps, PageHeap/Application Verifier for the consumer, and ETW capture from both `Microsoft.Windows.WESP.Driver` and `Microsoft.Windows.WESP.Client`.

## Disclosure-quality conclusion

At present there is no responsibly supportable claim of kernel compromise or authorization bypass. EC-01 and EC-02 are definite caller-process denial-of-service defects; EC-03 is a strong notification/resource-loss defect awaiting impact confirmation. EH-01 through EH-06 are prioritized experiments, not findings.

The most promising route to a material security result is the intersection of cross-client policy and capability tiers, followed by nested rule parser fuzzing and queue cancellation races. Any stronger conclusion should include exact build, token attributes, protection level, test-signing state, request bytes, NTSTATUS/HRESULT, and a minimal reproducer.

## External corroboration

Microsoft's [Windows Resiliency Initiative](https://www.microsoft.com/en-us/windows/business/windows-resiliency-initiative) describes WESP's role in moving endpoint security outside the kernel. The permission/PPL/test-signing observations above are corroborated—but not proven for this exact sample—by [independent WESP runtime research](https://jonny-jhnson.dev/blog/a-first-look-inside-the-windows-endpoint-security-platform/). An earlier consumer implementation is available as [WespConsumerPOC](https://github.com/jonny-jhnson/WespConsumerPOC); its build differences make version-pinning essential.
