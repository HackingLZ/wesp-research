# Notification capture and decoding

`monitor-process --capture FILE.jsonl` copies the confirmed `0x80`-byte common event prefix and at most 4 MiB of out-of-line payload before completing the notification. Each line is `wesplab.notification-capture.v1`; `truncated` and `payload_readable` prevent partial evidence from looking complete.

Decode captures with:

```sh
python wesplab.py notification-decode notifications.jsonl -o decoded.json
```

The decoder recognizes the confirmed ProcessCreate ID (`1000`), instance ID, rule GUID, queue GUID, hashes, entropy, and bounded ASCII/UTF-16 strings. It accepts every recovered event family through the same opaque-preserving envelope. Unknown layouts remain labeled `Unknown`; raw event and external bytes are retained exactly.

The recovered family catalog is `data/event-families-0.1.0.156346177.json`. Add numeric IDs or property decoders only after the target build produces both a controlled stimulus and an independently verified capture.

