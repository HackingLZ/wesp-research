#!/usr/bin/env python3
"""Attach only to an authorized WESP test consumer and record FilterSendMessage calls."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[2]))
from wesplab_ext import validate_wire_record

try:
    import frida
except ImportError:
    raise SystemExit("Frida is optional: install it in a dedicated environment with 'pip install frida-tools'")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("pid", type=int, help="PID of your own authorized WESP consumer")
    parser.add_argument("-o", "--output", type=Path, required=True)
    parser.add_argument("--schema", type=Path)
    parser.add_argument("--replay", type=Path, help="replay one validated capture through the observed live port")
    parser.add_argument("--allow-mutating", action="store_true")
    parser.add_argument("--doctor", type=Path, help="required exact-match doctor JSON for mutating replay")
    parser.add_argument("--duration", type=float, help="record for this many seconds instead of waiting for Enter")
    parser.add_argument("--replay-delay", type=float,
                        help="seconds to wait for a normal request before replay instead of waiting for Enter")
    args = parser.parse_args()
    agent_path = Path(__file__).with_name("wesp_wire_agent.js")
    schemas = json.loads(args.schema.read_text()) if args.schema else {"schemas": {}}
    session = frida.attach(args.pid)
    script = session.create_script(agent_path.read_text(encoding="utf-8"))
    stream = args.output.open("a", encoding="utf-8")

    def message(value, _data):
        if value.get("type") == "send":
            stream.write(json.dumps(value["payload"], separators=(",", ":")) + "\n")
            stream.flush()
        else:
            print(json.dumps(value), file=sys.stderr)

    script.on("message", message)
    script.load()
    script.post({"type": "configure", "payload": schemas})
    if args.replay:
        if args.replay_delay is None:
            print("Trigger one normal WESP query in the attached consumer, then press Enter.", file=sys.stderr)
            input()
        else:
            if args.replay_delay < 0:
                raise SystemExit("--replay-delay must be non-negative")
            time.sleep(args.replay_delay)
        record = json.loads(args.replay.read_text(encoding="utf-8-sig"))
        validation = validate_wire_record(record)
        if not validation["valid"]:
            raise SystemExit("replay refused: " + "; ".join(validation["errors"]))
        if args.allow_mutating:
            marker = Path(r"C:\ProgramData\wesplab\LAB_MACHINE")
            if not marker.exists():
                raise SystemExit(f"mutating replay requires disposable-VM marker: {marker}")
            if not args.doctor:
                raise SystemExit("mutating replay requires --doctor with an exact-match preflight")
            doctor = json.loads(args.doctor.read_text(encoding="utf-8-sig"))
            if not doctor.get("target_version_match"):
                raise SystemExit("mutating replay refused: doctor does not report target_version_match")
        result = script.exports_sync.replay(record, args.allow_mutating)
        print(json.dumps(result, indent=2))
    if args.duration is None:
        print("Recording. Press Enter to detach.", file=sys.stderr)
        input()
    else:
        if args.duration < 0:
            raise SystemExit("--duration must be non-negative")
        print(f"Recording for {args.duration:g} seconds.", file=sys.stderr)
        time.sleep(args.duration)
    session.detach()
    stream.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
