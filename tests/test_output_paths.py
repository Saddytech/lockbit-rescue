#!/usr/bin/env python3
import csv
import importlib.util
import sys
import tempfile
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
fake_tqdm = types.ModuleType("tqdm")
fake_tqdm.tqdm = lambda iterable=None, *args, **kwargs: iterable if iterable is not None else []
sys.modules.setdefault("tqdm", fake_tqdm)
spec = importlib.util.spec_from_file_location("lockbit_rescue", ROOT / "lockbit-rescue.py")
lockbit_rescue = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lockbit_rescue)


def test_duplicate_basenames_get_stable_unique_output_paths():
    source = Path("/source").resolve()
    output = Path("/recovered")
    plans = [
        (
            3,
            "abc123",
            None,
            [
                (90, "report.pdf.lockedext", "/source/a/report.pdf.lockedext", 100),
                (91, "report.pdf.lockedext", "/source/b/report.pdf.lockedext", 200),
                (92, "photo.jpg.lockedext", "/source/a/photo.jpg.lockedext", 300),
            ],
        )
    ]

    first, collisions = lockbit_rescue.build_output_paths(plans, source, output, ".lockedext")
    second, _ = lockbit_rescue.build_output_paths(plans, source, output, ".lockedext")

    a = first[("abc123", "/source/a/report.pdf.lockedext")]
    b = first[("abc123", "/source/b/report.pdf.lockedext")]
    photo = first[("abc123", "/source/a/photo.jpg.lockedext")]

    assert collisions == 2
    assert a != b
    assert a.name.startswith("report__") and a.suffix == ".pdf"
    assert b.name.startswith("report__") and b.suffix == ".pdf"
    assert photo == output / "group_abc123" / "photo.jpg"
    assert first == second


def test_manifest_has_one_header_and_expected_rows():
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "manifest.csv"
        lockbit_rescue.append_manifest(manifest, {"kek": "abc", "status": "recovered"})
        lockbit_rescue.append_manifest(manifest, {"kek": "def", "status": "suspect"})

        with open(manifest, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

    assert [row["kek"] for row in rows] == ["abc", "def"]
    assert [row["status"] for row in rows] == ["recovered", "suspect"]


if __name__ == "__main__":
    test_duplicate_basenames_get_stable_unique_output_paths()
    test_manifest_has_one_header_and_expected_rows()
