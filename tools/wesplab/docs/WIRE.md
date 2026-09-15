# Wire recorder and replayer

The optional Frida adapter hooks `FilterSendMessage` inside an authorized consumer. It records the fixed request envelope, HRESULT, sizes, timing, and configured pointer regions into `wesplab.wire-capture.v1` JSONL. It does not inject into unrelated security products.

Install Frida in a dedicated environment inside the disposable VM, then attach to your own consumer:

```powershell
py -m pip install frida-tools
py .\optional\frida\record_wesp_wire.py PID -o wire.jsonl
python .\wesplab.py wire-validate wire.jsonl -o validation.json
```

For unattended lab validation, run `wesplab-runtime watch-clients 15`, attach
the recorder to that PID, and pass `--duration 10`. The helper repeatedly
issues only registered/connected-client enumeration requests.

The PyPI Frida 17.6.2 Windows wheel is x64. On a native Windows ARM64 consumer it
fails with `missing helper able to handle the given target`; use a native ARM64
Frida build when one is available. Offline capture validation remains supported.

Pointer schemas are maps keyed by decimal request ID. Each entry names an envelope pointer slot and either a fixed byte count or an envelope count/size slot. Captured pointers are represented as named regions plus relocations; original virtual addresses are evidence only.

The same adapter can replay one validated record through a live port observed after attachment. Read-only request IDs are allowed by default. Other IDs require `--allow-mutating`, the disposable-VM marker, and exact-match `doctor` JSON. Replay is same-process/same-session because Filter Manager endpoints are private and handles cannot be carried between processes or boots.

```powershell
py .\optional\frida\record_wesp_wire.py PID -o replay-log.jsonl `
  --replay capture.json --doctor doctor.json --allow-mutating
```

Syntactic validation cannot prove that all nested pointers were captured. Start with public-API-generated seeds and request `0x07`; never replay against a third-party product client.
