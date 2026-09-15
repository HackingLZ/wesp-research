#!/usr/bin/env python3
"""Offline WESP binary inspection, snapshot, diff, and protocol corpus tools."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import struct
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import wesplab_ext

TOOL_VERSION = "0.2.0"
TARGET_BUILD = "0.1.0.156346177+c3490e8c"


class PeError(ValueError):
    pass


@dataclass(frozen=True)
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int


class PeImage:
    def __init__(self, path: Path):
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < 0x40 or self.data[:2] != b"MZ":
            raise PeError(f"{path}: not a PE image")
        pe = struct.unpack_from("<I", self.data, 0x3C)[0]
        if pe + 24 > len(self.data) or self.data[pe:pe + 4] != b"PE\0\0":
            raise PeError(f"{path}: invalid PE signature")
        self.pe_offset = pe
        self.machine, self.section_count, self.timestamp = struct.unpack_from(
            "<HHI", self.data, pe + 4
        )
        optional_size = struct.unpack_from("<H", self.data, pe + 20)[0]
        optional = pe + 24
        magic = struct.unpack_from("<H", self.data, optional)[0]
        if magic not in (0x10B, 0x20B):
            raise PeError(f"{path}: unsupported optional header 0x{magic:x}")
        self.is_64 = magic == 0x20B
        self.image_size = struct.unpack_from("<I", self.data, optional + 56)[0]
        self.dll_characteristics = struct.unpack_from("<H", self.data, optional + 70)[0]
        directory = optional + (112 if self.is_64 else 96)
        self.export_rva, self.export_size = struct.unpack_from("<II", self.data, directory)
        table = optional + optional_size
        self.sections: list[Section] = []
        for index in range(self.section_count):
            off = table + index * 40
            if off + 40 > len(self.data):
                raise PeError(f"{path}: truncated section table")
            raw_name = self.data[off:off + 8].split(b"\0", 1)[0]
            vsize, va, rsize, roff = struct.unpack_from("<IIII", self.data, off + 8)
            flags = struct.unpack_from("<I", self.data, off + 36)[0]
            self.sections.append(
                Section(raw_name.decode("ascii", "replace"), va, vsize, roff, rsize, flags)
            )

    def rva_offset(self, rva: int) -> int:
        for section in self.sections:
            extent = max(section.virtual_size, section.raw_size)
            if section.virtual_address <= rva < section.virtual_address + extent:
                offset = section.raw_offset + (rva - section.virtual_address)
                if offset >= len(self.data):
                    break
                return offset
        raise PeError(f"{self.path}: RVA 0x{rva:x} is unmapped")

    def cstring(self, offset: int) -> str:
        end = self.data.find(b"\0", offset)
        if end < 0:
            raise PeError(f"{self.path}: unterminated export name")
        return self.data[offset:end].decode("ascii", "replace")

    def exports(self) -> list[str]:
        if not self.export_rva:
            return []
        off = self.rva_offset(self.export_rva)
        if off + 40 > len(self.data):
            raise PeError(f"{self.path}: truncated export directory")
        count = struct.unpack_from("<I", self.data, off + 24)[0]
        names_rva = struct.unpack_from("<I", self.data, off + 32)[0]
        names = self.rva_offset(names_rva)
        result = []
        for index in range(count):
            name_rva = struct.unpack_from("<I", self.data, names + index * 4)[0]
            result.append(self.cstring(self.rva_offset(name_rva)))
        return sorted(result)

    def likely_versions(self) -> list[str]:
        text = self.data.decode("utf-16le", "ignore")
        values = re.findall(r"\b\d+\.\d+\.\d+\.\d+(?:\+[0-9A-Za-z._-]+)?\b", text)
        return sorted(set(values))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def binary_record(path: Path) -> dict:
    image = PeImage(path)
    machines = {0x8664: "x64", 0xAA64: "arm64", 0x14C: "x86"}
    return {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": sha256(path),
        "machine": machines.get(image.machine, f"0x{image.machine:04x}"),
        "image_size": image.image_size,
        "dll_characteristics": f"0x{image.dll_characteristics:04x}",
        "versions": image.likely_versions(),
        "exports": image.exports(),
        "sections": [section.__dict__ for section in image.sections],
    }


def emit(value: object, output: Path | None = None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def cmd_inspect(args: argparse.Namespace) -> int:
    emit(binary_record(args.binary), args.output)
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    record = {
        "schema": "wesplab.snapshot.v1",
        "tool_version": TOOL_VERSION,
        "target_build": TARGET_BUILD,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "host": {"platform": platform.platform(), "machine": platform.machine()},
        "binaries": [binary_record(path) for path in args.binary],
    }
    emit(record, args.output)
    return 0


def keyed_exports(record: dict) -> set[str]:
    return set(record.get("exports", []))


def load_record(path: Path) -> dict:
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("schema") == "wesplab.snapshot.v1":
            if len(value.get("binaries", [])) != 1:
                raise ValueError("diff accepts a one-binary snapshot or a PE image")
            return value["binaries"][0]
        return value
    return binary_record(path)


def cmd_diff(args: argparse.Namespace) -> int:
    before, after = load_record(args.before), load_record(args.after)
    old_exports, new_exports = keyed_exports(before), keyed_exports(after)
    changes = {
        "schema": "wesplab.binary-diff.v1",
        "before": {k: before.get(k) for k in ("path", "sha256", "size", "machine", "versions")},
        "after": {k: after.get(k) for k in ("path", "sha256", "size", "machine", "versions")},
        "exports_added": sorted(new_exports - old_exports),
        "exports_removed": sorted(old_exports - new_exports),
        "changed": before.get("sha256") != after.get("sha256"),
    }
    emit(changes, args.output)
    return 1 if args.fail_on_change and changes["changed"] else 0


def expected_exports(path: Path) -> set[str]:
    exports = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("Esp") and stripped.replace("_", "").isalnum():
            exports.add(stripped)
    return exports


def cmd_abi_check(args: argparse.Namespace) -> int:
    expected = expected_exports(args.definition)
    actual = set(PeImage(args.binary).exports())
    result = {
        "schema": "wesplab.abi-check.v1",
        "binary": str(args.binary.resolve()),
        "definition": str(args.definition.resolve()),
        "expected_count": len(expected),
        "actual_count": len(actual),
        "missing": sorted(expected - actual),
        "unexpected": sorted(actual - expected),
        "exact": expected == actual,
    }
    emit(result, args.output)
    return 0 if result["exact"] else 1


def cmd_state_diff(args: argparse.Namespace) -> int:
    before = json.loads(args.before.read_text(encoding="utf-8-sig"))
    after = json.loads(args.after.read_text(encoding="utf-8-sig"))
    result = {"schema": "wesplab.state-diff.v1"}
    changed = False
    for kind in ("registered", "connected"):
        old, new = set(before.get(kind, [])), set(after.get(kind, []))
        result[f"{kind}_added"] = sorted(new - old)
        result[f"{kind}_removed"] = sorted(old - new)
        changed |= old != new
    result["changed"] = changed
    emit(result, args.output)
    return 1 if args.fail_on_change and changed else 0


def protocol_rows(path: Path) -> list[dict[str, str]]:
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"))) for line in lines[1:] if line.strip()]


def cmd_protocol(args: argparse.Namespace) -> int:
    rows = protocol_rows(args.table)
    if args.kind:
        rows = [row for row in rows if row.get("kind") == args.kind]
    if args.id is not None:
        wanted = args.id.lower().removeprefix("0x")
        rows = [row for row in rows if row.get("id", "").lower().removeprefix("0x") == wanted]
    emit(rows, args.output)
    return 0


def cmd_corpus(args: argparse.Namespace) -> int:
    rows = protocol_rows(args.table)
    seeds = []
    for row in rows:
        seeds.append({
            "schema": "wesplab.protocol-seed.v1",
            "build": TARGET_BUILD,
            "kind": row.get("kind"),
            "id": row.get("id"),
            "name": row.get("name"),
            "mutation_stage": 0,
            "notes": "metadata seed; obtain relocatable payload from an authorized VM capture",
        })
    emit({"seeds": seeds}, args.output)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="wesplab", description="WESP research toolkit (offline component)")
    root.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    commands = root.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser("inspect", help="inspect a PE without third-party packages")
    inspect.add_argument("binary", type=Path)
    inspect.add_argument("-o", "--output", type=Path)
    inspect.set_defaults(func=cmd_inspect)

    snapshot = commands.add_parser("snapshot", help="record normalized PE metadata")
    snapshot.add_argument("binary", type=Path, nargs="+")
    snapshot.add_argument("-o", "--output", type=Path)
    snapshot.set_defaults(func=cmd_snapshot)

    diff = commands.add_parser("diff", help="compare PE images or one-binary snapshots")
    diff.add_argument("before", type=Path)
    diff.add_argument("after", type=Path)
    diff.add_argument("-o", "--output", type=Path)
    diff.add_argument("--fail-on-change", action="store_true")
    diff.set_defaults(func=cmd_diff)

    default_def = Path(__file__).with_name("data") / "espclient-0.1.0.156346177.def"
    abi = commands.add_parser("abi-check", help="compare a DLL with the exact 120-export ABI")
    abi.add_argument("binary", type=Path)
    abi.add_argument("--definition", type=Path, default=default_def)
    abi.add_argument("-o", "--output", type=Path)
    abi.set_defaults(func=cmd_abi_check)

    state_diff = commands.add_parser("state-diff", help="compare two live snapshot JSON files")
    state_diff.add_argument("before", type=Path)
    state_diff.add_argument("after", type=Path)
    state_diff.add_argument("-o", "--output", type=Path)
    state_diff.add_argument("--fail-on-change", action="store_true")
    state_diff.set_defaults(func=cmd_state_diff)

    default_table = Path(__file__).with_name("data") / "protocol-0.1.0.156346177.tsv"
    protocol = commands.add_parser("protocol", help="query recovered connection/request IDs")
    protocol.add_argument("--table", type=Path, default=default_table)
    protocol.add_argument("--kind", choices=("connect", "request"))
    protocol.add_argument("--id")
    protocol.add_argument("-o", "--output", type=Path)
    protocol.set_defaults(func=cmd_protocol)

    corpus = commands.add_parser("corpus", help="generate safe metadata seeds for VM capture")
    corpus.add_argument("--table", type=Path, default=default_table)
    corpus.add_argument("-o", "--output", type=Path, required=True)
    corpus.set_defaults(func=cmd_corpus)

    wesplab_ext.add_commands(commands)
    return root


def main() -> int:
    try:
        args = parser().parse_args()
        return args.func(args)
    except (OSError, PeError, ValueError, json.JSONDecodeError) as error:
        print(f"wesplab: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
