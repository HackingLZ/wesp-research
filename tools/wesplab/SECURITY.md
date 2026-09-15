# Security policy

This project studies a preview, undocumented Windows security interface. Do not report failures from version-skewed binaries as vulnerabilities.

For a suspected Microsoft vulnerability:

1. reproduce on an unmodified current Insider build;
2. record `doctor --json`, exact hashes, token context, and ETW;
3. minimize the trigger without testing third-party production clients;
4. report privately through the Microsoft Security Response Center portal;
5. do not publish exploit details before coordinated disclosure.

For a bug in wesplab, include the command, build architecture, compiler, exit code, and sanitized output. Never attach proprietary endpoint product policy or customer data.
