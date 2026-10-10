"""
CLI Module for Sensitive Data Leak Detector (T1-PS7).
Provides command-line interface for scanning files and folders, configuring rules,
exporting reports, and integrating into CI/CD pipelines (FR-8.1 to FR-8.4).
"""

from __future__ import annotations
import argparse
import sys
from pathlib import Path
from typing import List

from .loader import load_file, load_folder, LoadedItem
from .detector import LeakDetector, Finding
from .reporter import LeakReporter
from .classifier import SEVERITY_ORDER, Severity
from .masker import MaskingStyle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakdetect",
        description="Sensitive Data Leak Detector for APIs (T1-PS7) - Offline API Response Security Scanner",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # 'scan' command
    scan_parser = subparsers.add_parser("scan", help="Scan API response file or folder for sensitive data leaks")
    scan_parser.add_argument("path", help="Path to a single .json, .jsonl, .txt, .log file or directory")
    scan_parser.add_argument("--rules", default=None, help="Custom rules file (.yaml or .json)")
    scan_parser.add_argument("--format", default="md", choices=["md", "html", "json", "csv"], help="Export format")
    scan_parser.add_argument("--output", default=None, help="Output file path for scan report")
    scan_parser.add_argument(
        "--min-severity",
        default="Low",
        choices=["Critical", "High", "Medium", "Low"],
        help="Minimum severity threshold to report (FR-8.3, TC-14)",
    )
    scan_parser.add_argument(
        "--masking-style",
        default="partial",
        choices=["partial", "full", "hash"],
        help="Masking style for reported values and masked copy (FR-5.3)",
    )
    scan_parser.add_argument("--recursive", "-r", action="store_true", help="Recursively scan subfolders")
    scan_parser.add_argument("--presidio", action="store_true", help="Enable Microsoft Presidio entity detection")
    scan_parser.add_argument("--save-masked", default=None, help="Save a sanitized copy of the input to this path (FR-5.4)")
    scan_parser.add_argument(
        "--fail-on",
        default=None,
        choices=["Critical", "High", "Medium", "Low"],
        help="Exit with code 1 if findings at or above this severity are detected (FR-8.4)",
    )

    return parser


def main(args: list[str] | None = None) -> int:
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        return 0

    if parsed.command == "scan":
        target_path = Path(parsed.path)
        if not target_path.exists():
            print(f"Error: Target path '{target_path}' does not exist.", file=sys.stderr)
            return 2

        # 1. Load target(s)
        loaded_items: List[LoadedItem] = []
        if target_path.is_file():
            loaded_items.append(load_file(target_path))
        else:
            try:
                loaded_items.extend(load_folder(target_path, recursive=parsed.recursive))
            except Exception as e:
                print(f"Error loading directory: {e}", file=sys.stderr)
                return 2

        if not loaded_items:
            print(f"Warning: No supported files (.json, .jsonl, .txt, .log) found at '{target_path}'.", file=sys.stderr)
            return 0

        # Check for individual file errors
        valid_items: List[LoadedItem] = []
        for itm in loaded_items:
            if itm.error and itm.content == "":
                print(f"Error loading {itm.source_name}: {itm.error}", file=sys.stderr)
            else:
                valid_items.append(itm)

        if not valid_items:
            print("Error: No files could be loaded.", file=sys.stderr)
            return 2

        # 2. Initialize detector
        detector = LeakDetector(
            rules_path=parsed.rules,
            enable_presidio=parsed.presidio,
            masking_style=parsed.masking_style,
        )

        # 3. Scan
        all_findings, masked_copies = detector.scan_multiple(valid_items)

        # 4. Filter by min-severity (TC-14)
        min_sev_rank = SEVERITY_ORDER.get(Severity(parsed.min_severity), 1)
        filtered_findings = [
            f for f in all_findings
            if SEVERITY_ORDER.get(Severity(f.severity), 1) >= min_sev_rank
        ]

        # 5. Reporter
        rule_name = Path(parsed.rules).name if parsed.rules else "default_rules.yaml"
        scanned_names = [itm.source_name for itm in valid_items]
        reporter = LeakReporter(
            findings=filtered_findings,
            files_scanned=scanned_names,
            rule_set_name=rule_name,
        )

        reporter.print_console_summary()

        # Save report if requested
        if parsed.output:
            out_file = Path(parsed.output)
            reporter.save_report(out_file, format_type=parsed.format)
            print(f"Report exported to: {out_file.resolve()}")

        # Save masked copy if requested (FR-5.4)
        if parsed.save_masked:
            out_masked = Path(parsed.save_masked)
            if len(valid_items) == 1:
                src_key = valid_items[0].source_name
                out_masked.write_text(masked_copies.get(src_key, ""), encoding="utf-8")
                print(f"Sanitized payload saved to: {out_masked.resolve()}")
            else:
                # If directory, save each masked copy
                out_masked.mkdir(parents=True, exist_ok=True)
                for item in valid_items:
                    dest = out_masked / (Path(item.source_name).name + ".masked")
                    dest.write_text(masked_copies.get(item.source_name, ""), encoding="utf-8")
                print(f"Sanitized payloads written to folder: {out_masked.resolve()}")

        # 6. CI Exit Code evaluation (FR-8.4)
        if parsed.fail_on:
            fail_rank = SEVERITY_ORDER.get(Severity(parsed.fail_on), 1)
            matching_failures = [
                f for f in filtered_findings
                if SEVERITY_ORDER.get(Severity(f.severity), 1) >= fail_rank
            ]
            if matching_failures:
                print(f"Pipeline check failed: Detected {len(matching_failures)} finding(s) at or above '{parsed.fail_on}'.", file=sys.stderr)
                return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
