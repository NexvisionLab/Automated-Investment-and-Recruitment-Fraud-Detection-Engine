#!/usr/bin/env python3
# Copyright © 2026 NexVision Lab.
# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
"""Materialize train/validation/test JSONL files from the canonical corpus."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def materialize(root: Path = ROOT) -> dict[str, int]:
    data_dir = root / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    temporary_paths: dict[str, Path] = {}
    handles = {}
    for name in ("train", "validation", "test"):
        handle = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n",
            prefix=f".{name}.", suffix=".tmp", dir=data_dir, delete=False,
        )
        handles[name] = handle
        temporary_paths[name] = Path(handle.name)
    counts = {name: 0 for name in handles}
    try:
        with (data_dir / "records.jsonl").open(encoding="utf-8") as source:
            for line in source:
                record = json.loads(line)
                split = record["split"]
                if split not in handles:
                    raise ValueError(f"unsupported split {split!r} in record {record.get('id', '<unknown>')}")
                handles[split].write(line)
                counts[split] += 1
        for handle in handles.values():
            handle.flush()
            os.fsync(handle.fileno())
        for handle in handles.values():
            handle.close()
        for name, temporary_path in temporary_paths.items():
            os.replace(temporary_path, data_dir / f"{name}.jsonl")
    except BaseException:
        for handle in handles.values():
            if not handle.closed:
                handle.close()
        for temporary_path in temporary_paths.values():
            temporary_path.unlink(missing_ok=True)
        raise
    return counts


def main() -> None:
    print(json.dumps(materialize(), sort_keys=True))


if __name__ == "__main__":
    main()
