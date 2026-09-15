"""Higher-level evidence, schema, rule, timeline, wire, and health tooling.

The formats in this module deliberately preserve unknown bytes.  WESP is an
unstable private ABI; a decoder must never silently turn an unverified layout
into a security conclusion.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import re
import struct
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

TARGET_BUILD = "0.1.0.156346177+c3490e8c"
MAX_BLOB = 64 * 1024 * 1024


EVENT_FAMILIES = [
    "ThreadCreate", "ThreadStart", "ThreadTerminate", "ProcessCreate",
    "ProcessTerminate", "ProcessLoadImage", "FileCreate", "FileOpen",
    "FileRead", "FileWrite", "FileCleanup", "FileCreateSection",
    "FileQueryInformation", "FileSetInformation", "FileSetSecurity",
    "FileQueryDirectoryInformation", "FileFsctl", "SetEa", "FileQueryOpen",
    "FileLock", "FileUnlock", "KtmTransactionCommit", "KtmTransactionRollback",
    "VolumeMount", "VolumeDismount", "VolumeFsctl", "PipeCreate",
    "MailslotCreate", "RegCreateKey", "RegOpenKey", "RegDeleteKey",
    "RegSetValueKey", "RegDeleteValueKey", "RegRenameKey", "RegReplaceKey",
    "RegRestoreKey", "RegSetKeySecurity", "RegQueryKey", "RegQueryValueKey",
    "RegSaveKey", "RegLoadKey", "RegEnumKey", "RegEnumValueKey",
    "ObHandleCreate", "ObHandleDuplicate", "BootLoadDriver",
]


def _emit(value: object, output: Path | None = None) -> None:
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if output:
        output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


def _records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8-sig")
    if not text.strip():
        return []
    if path.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    value = json.loads(text)
    if isinstance(value, list):
        return value
    if isinstance(value, dict) and isinstance(value.get("records"), list):
        return value["records"]
    return [value]


def _blob(record: dict[str, Any], name: str) -> bytes:
    value = record.get(name, "")
    if not isinstance(value, str) or len(value) > MAX_BLOB * 2:
        raise ValueError(f"{name}: invalid or oversized hex field")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{name}: malformed hex") from error


def _guid_le(value: bytes) -> str | None:
    if len(value) != 16:
        return None
    return "{" + str(uuid.UUID(bytes_le=value)).upper() + "}"


def _strings(blob: bytes) -> dict[str, list[str]]:
    ascii_values = [m.decode("ascii") for m in re.findall(rb"[ -~]{4,}", blob)[:32]]
    utf16_values: list[str] = []
    for match in re.findall(rb"(?:[ -~]\x00){4,}", blob)[:32]:
        utf16_values.append(match.decode("utf-16le", "replace"))
    return {"ascii": ascii_values, "utf16le": utf16_values}


def _entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = Counter(blob)
    return round(-sum((n / len(blob)) * math.log2(n / len(blob)) for n in counts.values()), 4)


def _decode_layout(blob: bytes, field: dict[str, Any]) -> Any:
    offset, kind = int(field["offset"]), field["type"]
    sizes = {"u8": 1, "u16": 2, "u32": 4, "u64": 8, "i32": 4, "i64": 8, "guid": 16}
    size = int(field.get("size", sizes.get(kind, 0)))
    if offset < 0 or size < 0 or offset + size > len(blob):
        raise ValueError("field exceeds captured buffer")
    raw = blob[offset:offset + size]
    if kind in {"u8", "u16", "u32", "u64"}:
        return int.from_bytes(raw, "little", signed=False)
    if kind in {"i32", "i64"}:
        return int.from_bytes(raw, "little", signed=True)
    if kind == "guid": return _guid_le(raw)
    if kind == "utf16le": return raw.decode("utf-16le", "replace").rstrip("\0")
    if kind == "ascii": return raw.decode("ascii", "replace").rstrip("\0")
    if kind == "bytes": return raw.hex()
    raise ValueError(f"unsupported layout type: {kind}")


def decode_notification(record: dict[str, Any], layouts: dict[str, Any] | None = None) -> dict[str, Any]:
    event = _blob(record, "event_data_hex")
    external = _blob(record, "external_payload_hex")
    prefix: dict[str, Any] = {}
    warnings: list[str] = []
    if len(event) >= 0x80:
        prefix = {
            "instance_id": struct.unpack_from("<Q", event, 0)[0],
            "rule_id": _guid_le(event[8:24]),
            "event_type": struct.unpack_from("<I", event, 0x78)[0],
        }
    else:
        warnings.append("event_data shorter than confirmed 0x80-byte prefix")
    supplied_type = record.get("event_type")
    event_type = prefix.get("event_type", supplied_type)
    layout = (layouts or {}).get("event_types", {}).get(str(event_type), {})
    family = layout.get("family") or ("ProcessCreate" if event_type == 1000 else
                                      record.get("event_family", "Unknown"))
    if supplied_type is not None and prefix and supplied_type != event_type:
        warnings.append("supplied event_type disagrees with captured prefix")
    properties = []
    for item in record.get("properties", []):
        raw = bytes.fromhex(item.get("value_hex", ""))
        properties.append({
            "id": item.get("id"), "type": item.get("type", "unknown"),
            "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "strings": _strings(raw), "value_hex": raw.hex(),
        })
    decoded_fields: dict[str, Any] = {}
    for field in layout.get("fields", []):
        try:
            source = event if field.get("source", "event_data") == "event_data" else external
            decoded_fields[field["name"]] = _decode_layout(source, field)
        except (KeyError, TypeError, ValueError) as error:
            warnings.append(f"layout field {field.get('name', '?')}: {error}")
    return {
        "schema": "wesplab.notification-decoded.v1",
        "timestamp_utc": record.get("timestamp_utc"),
        "queue_id": record.get("queue_id"),
        "event_family": family,
        "prefix": prefix,
        "event_data": {
            "size": len(event), "sha256": hashlib.sha256(event).hexdigest(),
            "strings": _strings(event), "hex": event.hex(),
        },
        "external_payload": {
            "size": len(external), "sha256": hashlib.sha256(external).hexdigest(),
            "entropy": _entropy(external), "strings": _strings(external),
            "hex": external.hex(),
        },
        "properties": properties,
        "decoded_fields": decoded_fields,
        "warnings": warnings + (["event layout is not yet build-validated; opaque bytes retained"]
                                if family == "Unknown" else []),
    }


def cmd_notification_decode(args: argparse.Namespace) -> int:
    layouts = json.loads(args.schema.read_text(encoding="utf-8-sig")) if args.schema else None
    decoded = [decode_notification(row, layouts) for row in _records(args.input)]
    result = {"schema": "wesplab.notification-decode-set.v1", "records": decoded}
    _emit(result, args.output)
    return 0


def _artifact_key(item: dict[str, Any]) -> str:
    return str(item.get("logical_name") or Path(item.get("path", "unknown")).name).lower()


def cmd_build_diff(args: argparse.Namespace) -> int:
    before = json.loads(args.before.read_text(encoding="utf-8-sig"))
    after = json.loads(args.after.read_text(encoding="utf-8-sig"))
    old = {_artifact_key(x): x for x in before.get("artifacts", before.get("binaries", []))}
    new = {_artifact_key(x): x for x in after.get("artifacts", after.get("binaries", []))}
    details = []
    for key in sorted(old.keys() & new.keys()):
        left, right = old[key], new[key]
        old_exports, new_exports = set(left.get("exports", [])), set(right.get("exports", []))
        fields = [name for name in ("sha256", "size", "version", "product_version", "machine",
                                    "section_count", "pe_timestamp", "image_size",
                                    "dll_characteristics", "signature_status", "signer")
                  if left.get(name) != right.get(name)]
        details.append({
            "artifact": key, "changed_fields": fields,
            "exports_added": sorted(new_exports - old_exports),
            "exports_removed": sorted(old_exports - new_exports),
        })
    result = {
        "schema": "wesplab.build-diff.v1",
        "before_build": before.get("windows_build"), "after_build": after.get("windows_build"),
        "artifacts_added": sorted(new.keys() - old.keys()),
        "artifacts_removed": sorted(old.keys() - new.keys()),
        "artifacts": details,
        "etw_schema_changed": before.get("etw_schema_sha256") != after.get("etw_schema_sha256"),
    }
    result["changed"] = bool(result["artifacts_added"] or result["artifacts_removed"] or
                             result["etw_schema_changed"] or
                             any(x["changed_fields"] or x["exports_added"] or
                                 x["exports_removed"] for x in details))
    _emit(result, args.output)
    return 1 if args.fail_on_change and result["changed"] else 0


COMPARISONS = {"eq", "ne", "lt", "le", "gt", "ge", "contains", "prefix", "suffix", "matches"}
BOOLEAN = {"and", "or", "xor"}


def _compile_filter(node: Any, path: str = "filter") -> dict[str, Any]:
    if node is None:
        return {"op": "true"}
    if not isinstance(node, dict):
        raise ValueError(f"{path}: expected object")
    op = str(node.get("op", "")).lower()
    if op in BOOLEAN:
        children = node.get("children")
        if not isinstance(children, list) or len(children) < 2:
            raise ValueError(f"{path}: {op} requires at least two children")
        return {"op": op, "children": [_compile_filter(x, f"{path}.children[{i}]")
                                        for i, x in enumerate(children)]}
    if op == "not":
        return {"op": "not", "child": _compile_filter(node.get("child"), f"{path}.child")}
    if op != "property":
        raise ValueError(f"{path}: op must be property/and/or/xor/not")
    family = str(node.get("family", "")).lower()
    if family not in {"event", "client", "token", "mailslot", "pipe", "ktm", "desktop",
                      "registry-object", "registry", "disk", "volume", "file-object",
                      "file", "stream", "process", "thread"}:
        raise ValueError(f"{path}: unknown property family")
    comparison = str(node.get("comparison", "")).lower()
    if comparison not in COMPARISONS:
        raise ValueError(f"{path}: unsupported comparison")
    prop = node.get("property")
    if not isinstance(prop, int) or prop < 0 or prop > 0xFFFFFFFF:
        raise ValueError(f"{path}: property must be uint32")
    value = node.get("value")
    if not isinstance(value, (bool, int, str)):
        raise ValueError(f"{path}: value must be boolean, integer, or string")
    return {"op": "property", "family": family, "property": prop,
            "comparison": comparison, "value": value}


def compile_rule_document(document: dict[str, Any]) -> dict[str, Any]:
    if document.get("schema") != "wesplab.rule.v1":
        raise ValueError("rule schema must be wesplab.rule.v1")
    event = document.get("event")
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    event_type = event.get("type")
    if not isinstance(event_type, (str, int)):
        raise ValueError("event.type must be a name or numeric ID")
    action = document.get("action", {})
    if action.get("type") not in {"notify", "allow", "block"}:
        raise ValueError("action.type must be notify, allow, or block")
    properties = event.get("properties", [])
    if not isinstance(properties, list) or any(not isinstance(x, int) or x < 0 for x in properties):
        raise ValueError("event.properties must be an array of non-negative integers")
    compiled = {
        "schema": "wesplab.rule-ir.v1", "abi": TARGET_BUILD,
        "id": document.get("id", "auto"), "event": {"type": event_type,
        "properties": properties}, "filter": _compile_filter(document.get("filter")),
        "action": action, "lifetime": document.get("lifetime", "temporary"),
        "order_group": int(document.get("order_group", 100)),
    }
    live_supported = (event_type in (1000, "ProcessCreate") and
                      compiled["filter"]["op"] == "true" and action.get("type") == "notify")
    compiled["adapter"] = {
        "live_supported": live_supported,
        "command": "wesplab-runtime monitor-process --write" if live_supported else None,
        "reason": None if live_supported else
            "descriptor/filter layout requires confirmation on the target build before live materialization",
    }
    return compiled


def cmd_rule_compile(args: argparse.Namespace) -> int:
    document = json.loads(args.input.read_text(encoding="utf-8-sig"))
    _emit(compile_rule_document(document), args.output)
    return 0


def _parse_time(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    try:
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).astimezone(timezone.utc).isoformat()
    except ValueError:
        return text


def _timeline_records(path: Path) -> Iterable[dict[str, Any]]:
    suffix = path.suffix.lower()
    if suffix in {".json", ".jsonl"}:
        yield from _records(path)
        return
    if suffix == ".csv":
        with path.open(encoding="utf-8-sig", newline="") as stream:
            yield from csv.DictReader(stream)
        return
    raise ValueError(f"unsupported timeline input: {path}")


def _event(row: dict[str, Any], source: Path) -> dict[str, Any]:
    timestamp = next((row.get(x) for x in ("timestamp_utc", "TimeCreated", "Timestamp",
                                            "EventHeader.TimeStamp") if row.get(x)), "")
    provider = next((row.get(x) for x in ("provider", "ProviderName", "Provider") if row.get(x)),
                    source.stem)
    name = next((row.get(x) for x in ("event_family", "EventName", "TaskName", "name")
                 if row.get(x)), row.get("event_type", "event"))
    return {"timestamp_utc": _parse_time(timestamp), "provider": str(provider),
            "name": str(name), "source": source.name, "data": row}


def _timeline_html(events: list[dict[str, Any]]) -> str:
    payload = json.dumps(events, separators=(",", ":")).replace("</", "<\\/")
    return """<!doctype html><meta charset=utf-8><title>WespLab timeline</title>
<style>body{font:14px system-ui;margin:24px;background:#10141c;color:#e8edf6}h1{margin:0 0 12px}
input{width:100%;box-sizing:border-box;padding:10px;background:#18202d;color:#fff;border:1px solid #42516a}
table{width:100%;border-collapse:collapse;margin-top:14px}th,td{text-align:left;padding:7px;border-bottom:1px solid #2b3546;vertical-align:top}
th{position:sticky;top:0;background:#10141c}code{white-space:pre-wrap;word-break:break-all;color:#a8c7fa}.muted{color:#91a0b7}</style>
<h1>WespLab correlated timeline</h1><div id=count class=muted></div><input id=q placeholder="Filter provider, event, source, or JSON">
<table><thead><tr><th>UTC</th><th>Provider</th><th>Event</th><th>Source</th><th>Data</th></tr></thead><tbody id=rows></tbody></table>
<script>const events=""" + payload + """;const q=document.querySelector('#q'),rows=document.querySelector('#rows'),count=document.querySelector('#count');
function esc(s){return String(s).replace(/[&<>\"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;'}[c]))}
function draw(){const needle=q.value.toLowerCase();const shown=events.filter(e=>JSON.stringify(e).toLowerCase().includes(needle));
count.textContent=shown.length+' of '+events.length+' events';rows.innerHTML=shown.map(e=>`<tr><td>${esc(e.timestamp_utc)}</td><td>${esc(e.provider)}</td><td>${esc(e.name)}</td><td>${esc(e.source)}</td><td><code>${esc(JSON.stringify(e.data,null,2))}</code></td></tr>`).join('')}
q.oninput=draw;draw()</script>"""


def cmd_timeline(args: argparse.Namespace) -> int:
    events = [_event(row, path) for path in args.input for row in _timeline_records(path)]
    events.sort(key=lambda x: x["timestamp_utc"])
    args.output.write_text(_timeline_html(events), encoding="utf-8")
    if args.json:
        _emit({"schema": "wesplab.timeline.v1", "events": events}, args.json)
    return 0


def validate_wire_record(record: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if record.get("schema") != "wesplab.wire-capture.v1":
        errors.append("record schema must be wesplab.wire-capture.v1")
    if record.get("abi") not in (None, TARGET_BUILD):
        errors.append("capture ABI does not match this adapter")
    envelope = _blob(record, "envelope_hex")
    if len(envelope) != 0x40:
        errors.append("envelope must be exactly 0x40 bytes")
    request_id = struct.unpack_from("<I", envelope, 0)[0] if len(envelope) >= 4 else None
    if request_id is not None and request_id > 0x1C:
        errors.append("request discriminant exceeds recovered range 0x00..0x1c")
    regions = record.get("regions", [])
    names: set[str] = set()
    total_region_bytes = 0
    for index, region in enumerate(regions):
        name = region.get("name")
        if not isinstance(name, str) or not name or name in names:
            errors.append(f"regions[{index}].name is missing or duplicate")
        names.add(name)
        try:
            total_region_bytes += len(_blob(region, "data_hex"))
        except ValueError as error:
            errors.append(str(error))
    if total_region_bytes > 16 * 1024 * 1024:
        errors.append("aggregate captured regions exceed 16 MiB validation limit")
    relocation_offsets: set[int] = set()
    for index, reloc in enumerate(record.get("relocations", [])):
        if reloc.get("region") not in names:
            errors.append(f"relocations[{index}] references unknown region")
        offset = reloc.get("envelope_offset")
        if not isinstance(offset, int) or offset < 0 or offset + 8 > 0x40 or offset % 8:
            errors.append(f"relocations[{index}] has invalid envelope offset")
        elif offset in relocation_offsets:
            errors.append(f"relocations[{index}] duplicates an envelope offset")
        else:
            relocation_offsets.add(offset)
    return {"schema": "wesplab.wire-validation.v1", "valid": not errors,
            "request_id": request_id, "errors": errors,
            "capture_only": True,
            "note": "live replay is intentionally delegated to the build-pinned VM harness"}


def cmd_wire_validate(args: argparse.Namespace) -> int:
    results = [validate_wire_record(x) for x in _records(args.input)]
    _emit({"schema": "wesplab.wire-validation-set.v1", "records": results}, args.output)
    return 0 if all(x["valid"] for x in results) else 1


def cmd_health(args: argparse.Namespace) -> int:
    rows = [row for path in args.input for row in _records(path)]
    gaps: list[float] = []
    parsed_times: list[datetime] = []
    drops = 0
    errors = 0
    latencies: list[float] = []
    state_changes = 0
    integrity_failures = 0
    missing_clients: set[str] = set()
    canaries: set[str] = set()
    evidence_parts: list[str] = []
    for row in rows:
        if row.get("schema") == "wesplab.canary-stimulus.v1" and row.get("marker"):
            canaries.add(str(row["marker"]).lower())
        else:
            evidence_parts.append(json.dumps(row, sort_keys=True).lower())
            for field in ("event_data_hex", "external_payload_hex"):
                try:
                    raw = bytes.fromhex(str(row.get(field, "")))
                    evidence_parts.append(raw.decode("ascii", "ignore").lower())
                    evidence_parts.append(raw.decode("utf-16le", "ignore").lower())
                except ValueError:
                    pass
        raw_time = row.get("timestamp_utc")
        if raw_time:
            try:
                parsed_times.append(datetime.fromisoformat(str(raw_time).replace("Z", "+00:00")))
            except ValueError:
                pass
        drops += int(row.get("dropped", row.get("drop_count", 0)) or 0)
        errors += int(bool(row.get("error") or row.get("hresult", 0)))
        if row.get("latency_ms") is not None:
            latencies.append(float(row["latency_ms"]))
        state_changes += int(row.get("schema") == "wesplab.state-change.v1")
        integrity_failures += int(row.get("espclient_integrity_ok") is False)
        integrity_failures += int(row.get("driver_integrity_ok") is False)
        missing_clients.update(str(x) for x in row.get("missing_expected_clients", []))
        errors += int(bool(row.get("snapshot_exit_code", 0)))
    parsed_times.sort()
    gaps = [(b - a).total_seconds() for a, b in zip(parsed_times, parsed_times[1:])]
    alerts = []
    if drops: alerts.append({"severity": "high", "kind": "notification-drops", "count": drops})
    if errors: alerts.append({"severity": "medium", "kind": "errors", "count": errors})
    if gaps and max(gaps) > args.max_gap:
        alerts.append({"severity": "medium", "kind": "delivery-gap",
                       "maximum_seconds": max(gaps), "threshold_seconds": args.max_gap})
    if integrity_failures:
        alerts.append({"severity": "high", "kind": "binary-integrity", "count": integrity_failures})
    if missing_clients:
        alerts.append({"severity": "high", "kind": "missing-expected-clients",
                       "clients": sorted(missing_clients)})
    evidence = "\n".join(evidence_parts)
    missing_canaries = sorted(marker for marker in canaries if marker not in evidence)
    if missing_canaries:
        alerts.append({"severity": "high", "kind": "canary-not-observed",
                       "markers": missing_canaries})
    result = {
        "schema": "wesplab.health-report.v1", "created_utc": datetime.now(timezone.utc).isoformat(),
        "records": len(rows), "drops": drops, "errors": errors, "state_changes": state_changes,
        "maximum_delivery_gap_seconds": max(gaps) if gaps else None,
        "canaries": {"generated": len(canaries), "missing": missing_canaries},
        "latency_ms": {"count": len(latencies), "average": round(sum(latencies) / len(latencies), 3)
                       if latencies else None, "maximum": max(latencies) if latencies else None},
        "alerts": alerts, "healthy": not alerts,
    }
    _emit(result, args.output)
    return 1 if args.fail_on_alert and alerts else 0


def cmd_authz_report(args: argparse.Namespace) -> int:
    rows = [row for path in args.input for row in _records(path)]
    matrix: dict[str, dict[str, dict[str, int]]] = {}
    for row in rows:
        principal = str(row.get("principal_label", row.get("user", "unknown")))
        target = str(row.get("target", "unknown"))
        result = row.get("result") or {}
        target_row = matrix.setdefault(target, {}).setdefault(principal, {})
        for name, value in result.items():
            if name.endswith("_hresult") and isinstance(value, int):
                target_row[name] = value
    differentials = []
    for target, principals in matrix.items():
        operations = sorted({operation for values in principals.values() for operation in values})
        for operation in operations:
            observed = {principal: values.get(operation) for principal, values in principals.items()}
            if len({value for value in observed.values() if value is not None}) > 1:
                differentials.append({"target": target, "operation": operation, "results": observed})
    report = {"schema": "wesplab.authz-report.v1", "row_count": len(rows),
              "matrix": matrix, "differentials": differentials}
    _emit(report, args.output)
    return 1 if args.fail_on_differential and differentials else 0


def add_commands(commands: argparse._SubParsersAction) -> None:
    notify = commands.add_parser("notification-decode", help="decode bounded notification captures")
    notify.add_argument("input", type=Path); notify.add_argument("-o", "--output", type=Path)
    default_layout = Path(__file__).with_name("data") / "notification-layouts-0.1.0.156346177.json"
    notify.add_argument("--schema", type=Path, default=default_layout)
    notify.set_defaults(func=cmd_notification_decode)

    build = commands.add_parser("build-diff", help="semantic diff of harvested WESP builds")
    build.add_argument("before", type=Path); build.add_argument("after", type=Path)
    build.add_argument("-o", "--output", type=Path); build.add_argument("--fail-on-change", action="store_true")
    build.set_defaults(func=cmd_build_diff)

    rule = commands.add_parser("rule-compile", help="validate and compile JSON rule DSL to versioned IR")
    rule.add_argument("input", type=Path); rule.add_argument("-o", "--output", type=Path)
    rule.set_defaults(func=cmd_rule_compile)

    timeline = commands.add_parser("timeline", help="correlate JSONL/JSON/CSV evidence into HTML")
    timeline.add_argument("input", type=Path, nargs="+"); timeline.add_argument("-o", "--output", type=Path, required=True)
    timeline.add_argument("--json", type=Path); timeline.set_defaults(func=cmd_timeline)

    wire = commands.add_parser("wire-validate", help="validate relocatable 0x40-byte wire captures")
    wire.add_argument("input", type=Path); wire.add_argument("-o", "--output", type=Path)
    wire.set_defaults(func=cmd_wire_validate)

    health = commands.add_parser("health", help="score notification/state JSON evidence")
    health.add_argument("input", type=Path, nargs="+"); health.add_argument("-o", "--output", type=Path)
    health.add_argument("--max-gap", type=float, default=60.0); health.add_argument("--fail-on-alert", action="store_true")
    health.set_defaults(func=cmd_health)

    authz = commands.add_parser("authz-report", help="summarize multi-principal authorization JSONL")
    authz.add_argument("input", type=Path, nargs="+"); authz.add_argument("-o", "--output", type=Path)
    authz.add_argument("--fail-on-differential", action="store_true")
    authz.set_defaults(func=cmd_authz_report)
