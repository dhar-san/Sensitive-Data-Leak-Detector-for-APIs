"""
Parser Module for Sensitive Data Leak Detector.
Walks JSON structures, records JSON paths, and scans plain text line-by-line.
Also inspects embedded strings (embedded JSON, URLs, headers).
"""

from __future__ import annotations
import json
import logging
import re
import urllib.parse
from typing import Any, Dict, Generator, List, Optional
from .loader import LoadedItem

logger = logging.getLogger("leakdetect.parser")


class ParsedItem:
    """Represents a discrete candidate value extracted from an API payload."""

    def __init__(
        self,
        location: str,
        key_name: str,
        value_str: str,
        raw_value: Any,
        parent_context: Optional[Dict[str, Any]] = None,
        is_json_node: bool = True,
    ):
        self.location = location
        self.key_name = key_name
        self.value_str = value_str
        self.raw_value = raw_value
        self.parent_context = parent_context or {}
        self.is_json_node = is_json_node

    def __repr__(self) -> str:
        return f"<ParsedItem loc={self.location} key={self.key_name} len={len(self.value_str)}>"


def walk_json(
    data: Any,
    current_path: str = "",
    parent_key: str = "",
    parent_obj: Optional[Dict[str, Any]] = None,
) -> Generator[ParsedItem, None, None]:
    """Recursively walks arbitrary JSON data structures (dict, list, primitives)
    and yields ParsedItem with canonical JSON path (e.g. data.users[0].email).
    """
    if isinstance(data, dict):
        for k, v in data.items():
            sub_path = f"{current_path}.{k}" if current_path else str(k)
            yield from walk_json(v, current_path=sub_path, parent_key=str(k), parent_obj=data)

    elif isinstance(data, list):
        for idx, item in enumerate(data):
            sub_path = f"{current_path}[{idx}]"
            yield from walk_json(item, current_path=sub_path, parent_key=parent_key, parent_obj=parent_obj)

    else:
        # Primitive value (str, int, float, bool, None)
        if data is not None:
            val_str = str(data)
            yield ParsedItem(
                location=current_path,
                key_name=parent_key,
                value_str=val_str,
                raw_value=data,
                parent_context=parent_obj or {},
                is_json_node=True,
            )

            # FR-2.5: Look inside string values for embedded JSON, query strings, headers
            if isinstance(data, str) and len(data) > 6:
                yield from inspect_embedded_string(val_str, current_path, parent_key, parent_obj)


def inspect_embedded_string(
    text: str,
    base_path: str,
    parent_key: str,
    parent_obj: Optional[Dict[str, Any]],
) -> Generator[ParsedItem, None, None]:
    """Inspects string for embedded JSON, query params, or auth tokens (FR-2.5)."""
    trimmed = text.strip()

    # Check for embedded JSON string
    if (trimmed.startswith("{") and trimmed.endswith("}")) or (
        trimmed.startswith("[") and trimmed.endswith("]")
    ):
        try:
            sub_json = json.loads(trimmed)
            yield from walk_json(
                sub_json,
                current_path=f"{base_path}[embedded_json]",
                parent_key=parent_key,
                parent_obj=parent_obj,
            )
        except Exception:
            pass

    # Check for URL query strings (e.g. ?token=ey... or ?api_key=...)
    if "?" in text and ("http://" in text or "https://" in text or "/" in text):
        try:
            parsed_url = urllib.parse.urlparse(text)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            for param_k, param_vals in query_params.items():
                for param_v in param_vals:
                    yield ParsedItem(
                        location=f"{base_path}?{param_k}",
                        key_name=param_k,
                        value_str=param_v,
                        raw_value=param_v,
                        parent_context=parent_obj,
                        is_json_node=True,
                    )
        except Exception:
            pass


def walk_plain_text(text: str) -> Generator[ParsedItem, None, None]:
    """Scans plain text line by line and records line numbers (FR-2.3)."""
    lines = text.splitlines()
    for idx, line in enumerate(lines, start=1):
        line_str = line.strip()
        if not line_str:
            continue
        yield ParsedItem(
            location=f"line {idx}",
            key_name="",
            value_str=line,
            raw_value=line,
            parent_context={},
            is_json_node=False,
        )


def extract_items(loaded_item: LoadedItem) -> List[ParsedItem]:
    """Given a LoadedItem, extracts all candidates to be evaluated by detection rules."""
    items: List[ParsedItem] = []

    if loaded_item.is_json and loaded_item.parsed_data is not None:
        try:
            if loaded_item.file_type == "jsonl" and isinstance(loaded_item.parsed_data, list):
                for row_idx, row in enumerate(loaded_item.parsed_data, start=1):
                    for item in walk_json(row, current_path=f"line_{row_idx}"):
                        items.append(item)
            else:
                for item in walk_json(loaded_item.parsed_data):
                    items.append(item)
        except Exception as exc:
            logger.warning("Error parsing JSON tree for '%s': %s. Falling back to line-by-line.", loaded_item.source_name, exc)
            for item in walk_plain_text(loaded_item.content):
                items.append(item)
    else:
        # Fallback to plain text line-by-line (FR-2.4)
        for item in walk_plain_text(loaded_item.content):
            items.append(item)

    return items


def parse_target(loaded: LoadedItem) -> List[ParsedItem]:
    """Convenience alias for extracting items."""
    return extract_items(loaded)
