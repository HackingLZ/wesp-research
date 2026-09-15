# Rule DSL

`wesplab.rule.v1` describes an event, requested property IDs, Boolean filter tree, action, lifetime, and order group. Leaf filters use a recovered property family, numeric property ID, comparison, and typed scalar value. Composite operations are `and`, `or`, `xor`, and `not`.

```sh
python wesplab.py rule-compile examples/process-create.rule.json -o rule-ir.json
python wesplab.py rule-compile examples/filtered-process.rule.json -o filtered-ir.json
```

The compiler validates the entire tree and emits build-pinned `wesplab.rule-ir.v1`. The adapter marks whether the plan can be materialized by the current runtime. Only the unfiltered temporary ProcessCreate notification path is confirmed and maps to `monitor-process`; filtered rules and other families remain useful reproducible test vectors but are not sent live with guessed structures.

`Invoke-WespRule.ps1 -Rule examples\process-create.rule.json` compiles again at execution time, refuses an unsupported adapter, and invokes the confirmed temporary monitor with capture enabled.

Before enabling a new adapter, confirm structure sizes/offsets, public constructor argument types, success and failure cleanup, an expected positive match, an expected negative match, and independent ETW observation on the exact build.
