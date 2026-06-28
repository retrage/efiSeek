#!/usr/bin/env python3
import argparse
import csv
import json
from pathlib import Path


def parse_int_string(value):
    if value is None or value == "":
        return ""
    try:
        return int(value)
    except (TypeError, ValueError):
        return ""


def parse_offset_hex(value):
    parsed = parse_int_string(value)
    if parsed == "":
        return ""
    return f"0x{parsed:x}"


def count_object(obj, key):
    value = obj.get(key, {})
    return len(value) if isinstance(value, dict) else 0


def triage_bucket(target):
    upper = (target or "").upper()
    if upper in {"EFI_BOOT_SERVICES", "EFI_RUNTIME_SERVICES"}:
        return "external_table_high_confidence"
    if "_SMM_" in upper or upper.startswith("EFI_SMM_") or "_MM_" in upper or upper.startswith("EFI_MM_"):
        return "smm_named_protocol_low_confidence"
    if "PROTOCOL" in upper:
        return "protocol_interface_needs_provenance"
    if upper:
        return "unknown_target"
    return "missing_target"


def read_jsonl(path):
    rows = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise SystemExit(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
    return rows


def read_status(path):
    if path is None or not path.exists():
        return {}
    status = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        for row in reader:
            status[row.get("input_path", "")] = row
    return status


def write_csv(path, fieldnames, rows):
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def meta_for(row):
    meta = row.get("efiSeekMeta")
    return meta if isinstance(meta, dict) else {}


def interrupt_counts(meta):
    interrupts = meta.get("interrupts", {})
    if not isinstance(interrupts, dict):
        interrupts = {}
    return {
        "child_smi_count": count_object(interrupts, "child"),
        "sw_smi_count": count_object(interrupts, "swSmi"),
        "hw_smi_count": count_object(interrupts, "hwSmi"),
    }


def build_summary(rows, statuses):
    summary = []
    seen_inputs = set()
    for row in rows:
        meta = meta_for(row)
        input_path = row.get("inputPath", "")
        seen_inputs.add(input_path)
        status = statuses.get(input_path, {})
        counts = interrupt_counts(meta)
        callouts = meta.get("smm callouts", {})
        callout_roots = meta.get("callout roots", {})
        locate_protocol = meta.get("locate protocol", {})
        install_protocol = meta.get("install protocol", {})

        summary.append({
            "input_path": input_path,
            "program": row.get("program", ""),
            "md5": row.get("md5", ""),
            "has_meta": row.get("hasMeta", False),
            "exit_code": status.get("exit_code", ""),
            "smm_callout_count": len(callouts) if isinstance(callouts, dict) else 0,
            "callout_root_count": len(callout_roots) if isinstance(callout_roots, dict) else 0,
            "locate_protocol_count": len(locate_protocol) if isinstance(locate_protocol, dict) else 0,
            "install_protocol_count": len(install_protocol) if isinstance(install_protocol, dict) else 0,
            **counts,
            "log": status.get("log", ""),
            "console": status.get("console", ""),
        })
    for input_path, status in sorted(statuses.items()):
        if input_path in seen_inputs:
            continue
        summary.append({
            "input_path": input_path,
            "program": "",
            "md5": "",
            "has_meta": False,
            "exit_code": status.get("exit_code", ""),
            "smm_callout_count": 0,
            "callout_root_count": 0,
            "locate_protocol_count": 0,
            "install_protocol_count": 0,
            "child_smi_count": 0,
            "sw_smi_count": 0,
            "hw_smi_count": 0,
            "log": status.get("log", ""),
            "console": status.get("console", ""),
        })
    return summary


def build_detections(rows):
    detections = []
    for row in rows:
        meta = meta_for(row)
        callouts = meta.get("smm callouts", {})
        if not isinstance(callouts, dict):
            continue
        for offset, callout in sorted(callouts.items(), key=lambda item: parse_int_string(item[0])):
            target = callout.get("target", "")
            detections.append({
                "input_path": row.get("inputPath", ""),
                "program": row.get("program", ""),
                "offset": parse_offset_hex(offset),
                "offset_decimal": offset,
                "function_name": callout.get("function name", ""),
                "function_offset": parse_offset_hex(callout.get("function offset")),
                "target": target,
                "target_offset": parse_offset_hex(callout.get("target offset")),
                "triage_bucket": triage_bucket(target),
            })
    return detections


def build_protocols(rows):
    protocols = []
    for row in rows:
        meta = meta_for(row)
        for api_key, api_name in (
            ("locate protocol", "locate"),
            ("install protocol", "install"),
        ):
            entries = meta.get(api_key, {})
            if not isinstance(entries, dict):
                continue
            for offset, protocol in sorted(entries.items(), key=lambda item: parse_int_string(item[0])):
                protocols.append({
                    "input_path": row.get("inputPath", ""),
                    "program": row.get("program", ""),
                    "api": api_name,
                    "offset": parse_offset_hex(offset),
                    "offset_decimal": offset,
                    "function_name": protocol.get("function name", ""),
                    "name": protocol.get("name", ""),
                    "guid": protocol.get("guid", ""),
                    "interface_offset": parse_offset_hex(protocol.get("interface offset")),
                    "origin": protocol.get("origin", ""),
                })
    return protocols


def main():
    parser = argparse.ArgumentParser(description="Summarize efiSeek corpus JSONL output.")
    parser.add_argument("meta_jsonl", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--status", type=Path)
    args = parser.parse_args()

    rows = read_jsonl(args.meta_jsonl) if args.meta_jsonl.exists() else []
    statuses = read_status(args.status)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    summary = build_summary(rows, statuses)
    detections = build_detections(rows)
    protocols = build_protocols(rows)

    write_csv(args.output_dir / "summary.csv", [
        "input_path", "program", "md5", "has_meta", "exit_code",
        "smm_callout_count", "callout_root_count", "child_smi_count",
        "sw_smi_count", "hw_smi_count", "locate_protocol_count",
        "install_protocol_count", "log", "console",
    ], summary)

    write_csv(args.output_dir / "detections.csv", [
        "input_path", "program", "offset", "offset_decimal", "function_name",
        "function_offset", "target", "target_offset", "triage_bucket",
    ], detections)

    write_csv(args.output_dir / "protocols.csv", [
        "input_path", "program", "api", "offset", "offset_decimal",
        "function_name", "name", "guid", "interface_offset", "origin",
    ], protocols)

    print(f"programs={len(summary)} detections={len(detections)}")
    print(f"summary={args.output_dir / 'summary.csv'}")
    print(f"detections={args.output_dir / 'detections.csv'}")
    print(f"protocols={args.output_dir / 'protocols.csv'}")


if __name__ == "__main__":
    main()
