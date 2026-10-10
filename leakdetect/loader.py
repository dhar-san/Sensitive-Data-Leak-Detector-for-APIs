"""
Input Loader Module for Sensitive Data Leak Detector.
Handles single files, folders, strings, JSON, JSON Lines, and text files.
"""

from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("leakdetect.loader")

SUPPORTED_EXTENSIONS = {".json", ".jsonl", ".txt", ".log"}


class LoadedItem:
    """Represents a loaded source item to be scanned."""

    def __init__(
        self,
        source_name: str,
        content: str,
        file_type: str,
        parsed_data: Optional[Any] = None,
        is_json: bool = False,
        error: Optional[str] = None,
    ):
        self.source_name = source_name
        self.content = content
        self.file_type = file_type
        self.parsed_data = parsed_data
        self.is_json = is_json
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_name": self.source_name,
            "file_type": self.file_type,
            "is_json": self.is_json,
            "error": self.error,
            "content_length": len(self.content),
        }


def load_string(text: str, name: str = "<inline_input>") -> LoadedItem:
    """Loads a string input (e.g. from notebook, CLI, or web UI)."""
    if not isinstance(text, str):
        text = str(text)

    # Attempt to parse as JSON or JSON Lines
    stripped = text.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or (
        stripped.startswith("[") and stripped.endswith("]")
    ):
        try:
            parsed = json.loads(text)
            return LoadedItem(
                source_name=name,
                content=text,
                file_type="json",
                parsed_data=parsed,
                is_json=True,
            )
        except Exception as exc:
            logger.warning("JSON parse failed for inline text: %s. Falling back to plain text.", exc)
            return LoadedItem(
                source_name=name,
                content=text,
                file_type="txt",
                parsed_data=None,
                is_json=False,
                error=f"JSON parse error: {exc}",
            )

    # Check if multiline JSON Lines
    if "\n" in stripped and stripped.startswith("{"):
        lines = stripped.splitlines()
        jsonl_items = []
        is_all_json = True
        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                jsonl_items.append(json.loads(line_str))
            except Exception:
                is_all_json = False
                break
        if is_all_json and jsonl_items:
            return LoadedItem(
                source_name=name,
                content=text,
                file_type="jsonl",
                parsed_data=jsonl_items,
                is_json=True,
            )

    # Default to plain text
    return LoadedItem(
        source_name=name,
        content=text,
        file_type="txt",
        parsed_data=None,
        is_json=False,
    )


def load_file(file_path: str | Path) -> LoadedItem:
    """Loads a single file from the given path.
    Validates existence, readability, and file extension.
    """
    path = Path(file_path)

    if not path.exists():
        err = f"File not found: '{path}'"
        logger.error(err)
        return LoadedItem(source_name=str(path), content="", file_type="unknown", error=err)

    if not path.is_file():
        err = f"Path is not a regular file: '{path}'"
        logger.error(err)
        return LoadedItem(source_name=str(path), content="", file_type="unknown", error=err)

    ext = path.suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        err = f"Unsupported file type '{ext}'. Supported: {', '.join(sorted(SUPPORTED_EXTENSIONS))}"
        logger.error(err)
        return LoadedItem(source_name=str(path), content="", file_type=ext or "unknown", error=err)

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        err = f"Failed to read file '{path}': {exc}"
        logger.error(err)
        return LoadedItem(source_name=str(path), content="", file_type=ext, error=err)

    # Parse based on extension
    if ext == ".json":
        try:
            parsed = json.loads(content)
            return LoadedItem(
                source_name=str(path),
                content=content,
                file_type="json",
                parsed_data=parsed,
                is_json=True,
            )
        except Exception as exc:
            logger.warning("File '%s' contains malformed JSON (%s). Scanning as plain text.", path, exc)
            return LoadedItem(
                source_name=str(path),
                content=content,
                file_type="json",
                parsed_data=None,
                is_json=False,
                error=f"Malformed JSON: {exc}",
            )
    elif ext == ".jsonl":
        jsonl_items = []
        is_all_json = True
        for line in content.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            try:
                jsonl_items.append(json.loads(line_s))
            except Exception as exc:
                is_all_json = False
                logger.warning("JSONL parse error on line in '%s': %s", path, exc)
                break
        if is_all_json and jsonl_items:
            return LoadedItem(
                source_name=str(path),
                content=content,
                file_type="jsonl",
                parsed_data=jsonl_items,
                is_json=True,
            )
        else:
            return LoadedItem(
                source_name=str(path),
                content=content,
                file_type="jsonl",
                parsed_data=None,
                is_json=False,
                error="Some JSON Lines failed parsing, scanning as plain text",
            )
    else:
        # .txt or .log
        return LoadedItem(
            source_name=str(path),
            content=content,
            file_type=ext.lstrip("."),
            parsed_data=None,
            is_json=False,
        )


def load_folder(folder_path: str | Path, recursive: bool = False) -> List[LoadedItem]:
    """Loads every supported file in a folder, with optional recursion."""
    path = Path(folder_path)
    if not path.exists():
        raise FileNotFoundError(f"Directory not found: '{path}'")
    if not path.is_dir():
        raise NotADirectoryError(f"Path is not a directory: '{path}'")

    results: List[LoadedItem] = []
    pattern = "**/*" if recursive else "*"

    for p in sorted(path.glob(pattern)):
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
            results.append(load_file(p))

    return results
