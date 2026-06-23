#!/usr/bin/env python3
"""
lockbit-rescue.py
=================
End-to-end recovery tool for files encrypted by LockBit 3.0 ("Black") /
CriptomanGizmo, exploiting the documented keystream-reuse weakness.

Designed to be runnable by non-experts:
  python3 lockbit-rescue.py <SOURCE_DIR> <OUTPUT_DIR>

It will:
  1) Auto-detect the ransomware extension (random 9-char suffix per attack)
  2) Scan SOURCE_DIR for encrypted files
  3) Group files by their RSA-encrypted KEK fingerprint (same batch == same keystream)
  4) For each group, use the file with the longest original filename as the
     "oracle" (it provides enough known plaintext to recover the keystream)
  5) Decrypt all other files in the group whose footer-encryption-info
     length fits within the recovered keystream
  6) Save recovered files to OUTPUT_DIR/group_<kek>/<original_name>
     (suffixing duplicate basenames so outputs do not collide)
  7) Write manifest.csv with source/output/status mapping
  8) Verify each output with libmagic and skip writes for raw "data" results

Requires:
  - The `stream-reuse` binary (built from yohanes/lockbit-v3-linux-decryptor)
  - The `file` command (libmagic)
  - Python 3.8+ and `tqdm` (pip install tqdm)

Usage examples:
  # Basic
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered

  # Custom extension + no extension filter + smaller min size
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered \
      --ext .MoHsVxKYI --min-size 4096 --no-extension-filter

  # Specify path to stream-reuse if it's not next to this script
  python3 lockbit-rescue.py /mnt/infected /mnt/recovered \
      --stream-reuse /opt/lockbit-v3-linux-decryptor/stream-reuse
"""

import argparse
import collections
import csv
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

try:
    from tqdm import tqdm
except ImportError:
    print("ERROR: tqdm not installed. Run: pip install tqdm  (or: pip install -r requirements.txt)")
    sys.exit(1)

# ----- Defaults -----
DEFAULT_COMMON_EXTS = {
    # images
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "heic",
    "raw", "cr2", "nef", "arw", "dng",
    # documents
    "pdf", "doc", "docx", "odt", "rtf", "txt", "md",
    "xls", "xlsx", "ods", "csv", "ppt", "pptx", "odp",
    # archives
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz",
    # video
    "mp4", "mkv", "avi", "mov", "wmv", "flv", "webm", "m4v", "mpg", "mpeg",
    # audio
    "mp3", "wav", "flac", "aac", "ogg", "m4a", "wma",
    # design
    "psd", "ai", "eps", "indd", "sketch", "xd",
    # data / misc
    "html", "htm", "xml", "json",
    "pst", "ost", "eml", "msg", "vcf",
    "dwg", "dxf", "stl", "obj", "3ds",
    "epub", "mobi", "azw3",
    "db", "sqlite", "mdb", "accdb",
}

# Footer layout of LockBit 3.0 ("Black") encrypted files:
#   last 134 bytes total
#   [-134:-132] 2-byte little-endian footer-encryption-info length (fei_len)
#   [-132:-128] 4-byte checksum
#   [-128:    ] 128-byte RSA-encrypted Key Encryption Key (KEK)
# All files encrypted in the same batch share the same KEK blob,
# which is the fingerprint we use to group them.
FOOTER_TOTAL = 134
KEK_LEN = 128

# The known-plaintext we can recover from the long-named "oracle" file:
#   apLib-compressed UTF-16LE original filename + 18 bytes of footer metadata
# Coverage formula derived empirically: see TECHNICAL.md.
COVERAGE_OFFSET = 18
COVERAGE_BASE_FROM_FEI = 82  # bytes consumed by fixed metadata
MANIFEST_COLUMNS = [
    "kek", "source_path", "output_path", "original_name",
    "fei_len", "size", "status", "magic",
]


def detect_extension(source: Path, sample_limit: int = 5000) -> str:
    """Sample files to find the most common ransomware extension."""
    counts = collections.Counter()
    seen = 0
    for dirpath, _, files in os.walk(source):
        for fn in files:
            if "." not in fn:
                continue
            ext = "." + fn.rsplit(".", 1)[-1]
            # LockBit 3 extensions are 9 mixed-case alphanumeric chars
            if len(ext) == 10 and ext[1:].isalnum() and not ext[1:].isdigit():
                counts[ext] += 1
                seen += 1
                if seen >= sample_limit:
                    break
        if seen >= sample_limit:
            break
    if not counts:
        return ""
    ext, _ = counts.most_common(1)[0]
    return ext


def is_target(fname: str, ransom_ext: str, common_exts, no_extension_filter: bool) -> bool:
    if not fname.endswith(ransom_ext):
        return False
    base = fname[: -len(ransom_ext)]
    if "." not in base:
        # If the base has no extension at all, only accept when filter is disabled.
        return no_extension_filter
    if no_extension_filter:
        return True
    return base.rsplit(".", 1)[1].lower() in common_exts


def fmt_size(b: int) -> str:
    for u in ["B", "KB", "MB", "GB", "TB"]:
        if b < 1024:
            return f"{b:.1f}{u}"
        b /= 1024
    return f"{b:.1f}PB"


def copy_with_progress(src: Path, dst: Path, label: str, position: int = 2):
    sz = os.path.getsize(src)
    bar = tqdm(
        total=sz, desc=label, unit="B", unit_scale=True, unit_divisor=1024,
        leave=False, mininterval=0.3, position=position,
    )
    try:
        with open(src, "rb") as fi, open(dst, "wb") as fo:
            while True:
                buf = fi.read(1024 * 1024)
                if not buf:
                    break
                fo.write(buf)
                bar.update(len(buf))
    finally:
        bar.close()


def copy_atomic_with_progress(src: Path, dst: Path, label: str, position: int = 2):
    tmp = dst.with_name(f".{dst.name}.tmp")
    try:
        copy_with_progress(src, tmp, label, position)
        os.replace(tmp, dst)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def read_footer(path: Path):
    """Return (fei_len, kek_blob) from the last 134 bytes of an encrypted file."""
    with open(path, "rb") as f:
        f.seek(-FOOTER_TOTAL, 2)
        fei_len = struct.unpack("<H", f.read(2))[0]
        f.seek(-KEK_LEN, 2)
        kek_blob = f.read(KEK_LEN)
    return fei_len, kek_blob


def kek_fingerprint(kek_blob: bytes) -> str:
    return hashlib.md5(kek_blob).hexdigest()[:12]


def source_relpath(source: Path, path: str) -> str:
    p = Path(path).resolve()
    try:
        return str(p.relative_to(source))
    except ValueError:
        return p.name


def collision_safe_name(original_name: str, rel_path: str, collides: bool) -> str:
    if not collides:
        return original_name
    suffix = hashlib.sha1(rel_path.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    p = Path(original_name)
    if p.suffix:
        return f"{p.stem}__{suffix}{p.suffix}"
    return f"{original_name}__{suffix}"


def build_output_paths(plans, source: Path, output: Path, ransom_ext: str):
    """Return {(kek, encrypted_path): output_path}, suffixing duplicate basenames."""
    output_paths = {}
    collisions = 0
    for _, kek, _, targets in plans:
        name_keys = {tfname: tfname[: -len(ransom_ext)].casefold() for _, tfname, _, _ in targets}
        base_counts = collections.Counter(name_keys[tfname] for _, tfname, _, _ in targets)
        collisions += sum(c for c in base_counts.values() if c > 1)
        group_out = output / f"group_{kek}"
        for _, tfname, tpath, _ in targets:
            original = tfname[: -len(ransom_ext)]
            rel_path = source_relpath(source, tpath)
            out_name = collision_safe_name(original, rel_path, base_counts[name_keys[tfname]] > 1)
            output_paths[(kek, tpath)] = group_out / out_name
    return output_paths, collisions


def append_manifest(manifest: Path, row: dict):
    manifest.parent.mkdir(parents=True, exist_ok=True)
    needs_header = not manifest.exists() or manifest.stat().st_size == 0
    with open(manifest, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_COLUMNS)
        if needs_header:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in MANIFEST_COLUMNS})


def scan(source: Path, ransom_ext: str, common_exts, no_extension_filter: bool,
         min_size: int, max_size: int):
    """Walk source, group encrypted files by KEK fingerprint."""
    groups = collections.defaultdict(list)
    scanned = matched = skipped_size = 0
    bar = tqdm(desc="Scanning", unit="file", mininterval=0.5)
    for dirpath, _, files in os.walk(source):
        for fname in files:
            if not fname.endswith(ransom_ext):
                continue
            scanned += 1
            bar.update(1)
            fpath = Path(dirpath) / fname
            try:
                sz = os.path.getsize(fpath)
            except OSError:
                continue
            if sz < min_size:
                continue
            if sz > max_size:
                skipped_size += 1
                continue
            if not is_target(fname, ransom_ext, common_exts, no_extension_filter):
                continue
            matched += 1
            try:
                fei_len, kek_blob = read_footer(fpath)
            except (OSError, struct.error):
                continue
            groups[kek_fingerprint(kek_blob)].append((fei_len, fname, str(fpath), sz))
            bar.set_postfix({"match": matched, "grp": len(groups), "skipped_big": skipped_size})
    bar.close()
    return groups, scanned, matched, skipped_size


def build_plan(groups, ransom_ext: str):
    """Choose an oracle for each group and list decryptable targets."""
    plans = []
    for kek, members in groups.items():
        # Oracle = the file in this batch with the largest fei_len
        members.sort(key=lambda x: -x[0])
        oracle = members[0]
        coverage = (oracle[0] - COVERAGE_BASE_FROM_FEI) + COVERAGE_OFFSET
        targets = [m for m in members if m[0] <= coverage and m != oracle]
        if targets:
            plans.append((len(targets), kek, oracle, targets))
    plans.sort(key=lambda x: -x[0])
    return plans


def decrypt_target(tool: Path, target_path: Path, oracle_path: Path,
                   oracle_orig_name: str, scratch: Path, timeout: int = 600) -> Path:
    """Invoke stream-reuse. Returns the resulting 'decrypted' file path or None."""
    decrypted = scratch / "decrypted"
    if decrypted.exists():
        decrypted.unlink()
    try:
        subprocess.run(
            [str(tool), str(target_path), str(oracle_path), oracle_orig_name],
            cwd=str(scratch), capture_output=True, timeout=timeout,
        )
    except Exception:
        return None
    return decrypted if decrypted.exists() else None


def libmagic(path: Path) -> str:
    try:
        return subprocess.check_output(
            ["file", "-b", str(path)], timeout=10, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
    except Exception:
        return "unknown"


def is_bad_decrypt(ftype: str) -> bool:
    f = (ftype or "").lower()
    return f.startswith("data") or "corrupted" in f or f in ("", "empty")


def main():
    ap = argparse.ArgumentParser(
        description="Recover files encrypted by LockBit 3.0 via keystream reuse",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="See README.md and TECHNICAL.md for details.",
    )
    ap.add_argument("source", help="Directory containing encrypted files")
    ap.add_argument("output", help="Destination directory for recovered files")
    ap.add_argument("--ext", help='Ransomware extension (e.g. ".MoHsVxKYI"). Auto-detected if omitted.')
    ap.add_argument("--stream-reuse", default=None,
                    help="Path to the stream-reuse binary (default: ./stream-reuse next to script, "
                         "then ../lockbit-v3-linux-decryptor/stream-reuse)")
    ap.add_argument("--min-size", type=int, default=10 * 1024,
                    help="Minimum file size to attempt (default: 10240 bytes)")
    ap.add_argument("--max-size", type=int, default=1024 * 1024 * 1024,
                    help="Maximum file size to attempt (default: 1 GiB)")
    ap.add_argument("--no-extension-filter", action="store_true",
                    help="Try to decrypt ALL files, not only common formats")
    ap.add_argument("--scratch", default=None,
                    help="Scratch directory for per-job temp files (default: <output>/.scratch)")
    ap.add_argument("--timeout", type=int, default=600,
                    help="Per-file decryption timeout in seconds (default: 600)")
    args = ap.parse_args()

    source = Path(args.source).resolve()
    output = Path(args.output).resolve()
    if not source.is_dir():
        print(f"ERROR: source not a directory: {source}")
        sys.exit(2)
    output.mkdir(parents=True, exist_ok=True)

    # Locate stream-reuse
    here = Path(__file__).resolve().parent
    candidates = []
    if args.stream_reuse:
        candidates.append(Path(args.stream_reuse))
    candidates += [
        here / "stream-reuse",
        here.parent / "lockbit-v3-linux-decryptor" / "stream-reuse",
        Path("/usr/local/bin/stream-reuse"),
    ]
    tool = next((c for c in candidates if c.is_file() and os.access(c, os.X_OK)), None)
    if not tool:
        print("ERROR: stream-reuse binary not found. Try --stream-reuse PATH or run install.sh.")
        print("Looked in:")
        for c in candidates:
            print(f"  - {c}")
        sys.exit(3)
    print(f"[i] Using stream-reuse: {tool}")

    # Detect extension if not provided
    if not args.ext:
        print(f"[i] Detecting ransomware extension in {source} ...")
        args.ext = detect_extension(source)
        if not args.ext:
            print("ERROR: could not auto-detect extension. Re-run with --ext .EXAMPLEEXT")
            sys.exit(4)
        print(f"[i] Detected extension: {args.ext}")
    elif not args.ext.startswith("."):
        args.ext = "." + args.ext

    common_exts = DEFAULT_COMMON_EXTS
    if args.no_extension_filter:
        print("[i] Extension filter disabled — attempting ALL file types")

    # Scratch dir (per-job to avoid collisions when running multiple instances)
    scratch = Path(args.scratch) if args.scratch else (output / ".scratch")
    scratch.mkdir(parents=True, exist_ok=True)

    # --- Scan ---
    print(f"[*] Scanning {source} ...")
    t0 = time.time()
    groups, scanned, matched, skipped_big = scan(
        source, args.ext, common_exts, args.no_extension_filter,
        args.min_size, args.max_size,
    )
    print(f"[+] Scanned {scanned} encrypted files in {time.time()-t0:.1f}s")
    print(f"    match={matched}, groups={len(groups)}, skipped_too_big={skipped_big}")

    # --- Plan ---
    plans = build_plan(groups, args.ext)
    total_targets = sum(p[0] for p in plans)
    no_oracle = len(groups) - len(plans)
    output_paths, collision_targets = build_output_paths(plans, source, output, args.ext)
    manifest = output / "manifest.csv"
    print(f"[+] Plan: {len(plans)} decryptable groups / {len(groups)} total")
    print(f"    ({no_oracle} groups skipped — no oracle file with long enough filename)")
    print(f"    targets to attempt: {total_targets}")
    if collision_targets:
        print(f"    basename collisions protected: {collision_targets} target(s)")
    print(f"    output: {output}")
    print(f"    manifest: {manifest}")
    if total_targets == 0:
        print("[!] Nothing to decrypt. Probably no group has a long-named oracle.")
        return

    # --- Resume bookkeeping ---
    already = 0
    for _, kek, _, targets in plans:
        for _, _, tpath, _ in targets:
            if output_paths[(kek, tpath)].exists():
                already += 1
    if already:
        print(f"[i] Resume: {already} files already in output, will skip")

    total_ok = total_fail = 0
    remaining = total_targets - already
    overall = tqdm(total=remaining, desc="Overall", unit="file", mininterval=0.5, position=0)

    # --- Per-group decryption ---
    for gi, (n_targets, kek, oracle, targets) in enumerate(plans):
        oracle_fei_len, oracle_fname, oracle_path, oracle_sz = oracle
        oracle_orig = oracle_fname[: -len(args.ext)]
        group_out = output / f"group_{kek}"
        group_out.mkdir(parents=True, exist_ok=True)

        # Skip group if fully done
        existing = sum(1 for _, _, tp, _ in targets if output_paths[(kek, tp)].exists())
        if existing == len(targets):
            print(f"[GROUP {gi+1}/{len(plans)}] {kek} already complete, skip")
            continue

        print(f"\n[GROUP {gi+1}/{len(plans)}] {kek}  oracle=\"{oracle_orig[:60]}\" "
              f"({fmt_size(oracle_sz)})  -> {len(targets)} target(s)")

        # Stage oracle locally to avoid re-reading slow source over and over
        local_oracle = scratch / f"_oracle_{kek}{args.ext}"
        try:
            copy_with_progress(Path(oracle_path), local_oracle, f"  copy oracle {fmt_size(oracle_sz)}")
        except Exception as e:
            print(f"   [!] oracle copy failed: {e}")
            for fei_len, tfname, tpath, tsz in targets:
                torig = tfname[: -len(args.ext)]
                append_manifest(manifest, {
                    "kek": kek, "source_path": tpath,
                    "output_path": output_paths[(kek, tpath)],
                    "original_name": torig, "fei_len": fei_len, "size": tsz,
                    "status": "oracle_copy_failed",
                })
            overall.update(len(targets))
            continue

        grp_ok = grp_fail = 0
        grp_bar = tqdm(targets, desc=f"  {kek}", unit="file", leave=False,
                       mininterval=0.3, position=1)
        t_start = time.time()
        for (fei_len, tfname, tpath, tsz) in grp_bar:
            torig = tfname[: -len(args.ext)]
            out_path = output_paths[(kek, tpath)]
            short = (torig[:35] + "...") if len(torig) > 35 else torig
            grp_bar.set_postfix({"cur": short, "sz": fmt_size(tsz),
                                 "ok": grp_ok, "fail": grp_fail})

            if out_path.exists():
                grp_ok += 1
                append_manifest(manifest, {
                    "kek": kek, "source_path": tpath, "output_path": out_path,
                    "original_name": torig, "fei_len": fei_len, "size": tsz,
                    "status": "skipped_existing",
                })
                overall.update(1)
                continue

            local_target = scratch / f"_target{args.ext}"
            try:
                copy_with_progress(Path(tpath), local_target, f"    fetch {short}")
            except Exception:
                grp_fail += 1
                append_manifest(manifest, {
                    "kek": kek, "source_path": tpath, "output_path": out_path,
                    "original_name": torig, "fei_len": fei_len, "size": tsz,
                    "status": "copy_failed",
                })
                overall.update(1)
                continue

            decrypted = decrypt_target(tool, local_target, local_oracle,
                                       oracle_orig, scratch, args.timeout)
            if decrypted is None:
                grp_fail += 1
                append_manifest(manifest, {
                    "kek": kek, "source_path": tpath, "output_path": out_path,
                    "original_name": torig, "fei_len": fei_len, "size": tsz,
                    "status": "decrypt_failed",
                })
            else:
                ftype = libmagic(decrypted)
                if is_bad_decrypt(ftype):
                    grp_fail += 1
                    append_manifest(manifest, {
                        "kek": kek, "source_path": tpath, "output_path": out_path,
                        "original_name": torig, "fei_len": fei_len, "size": tsz,
                        "status": "suspect", "magic": ftype,
                    })
                    try: decrypted.unlink()
                    except: pass
                else:
                    try:
                        copy_atomic_with_progress(decrypted, out_path, f"    save {short}")
                        decrypted.unlink()
                        grp_ok += 1
                        append_manifest(manifest, {
                            "kek": kek, "source_path": tpath, "output_path": out_path,
                            "original_name": torig, "fei_len": fei_len, "size": tsz,
                            "status": "recovered", "magic": ftype,
                        })
                    except Exception:
                        grp_fail += 1
                        append_manifest(manifest, {
                            "kek": kek, "source_path": tpath, "output_path": out_path,
                            "original_name": torig, "fei_len": fei_len, "size": tsz,
                            "status": "save_failed", "magic": ftype,
                        })
                        try: decrypted.unlink()
                        except: pass

            try: local_target.unlink()
            except: pass
            overall.update(1)

        grp_bar.close()
        print(f"   GROUP DONE {kek}: {grp_ok} ok / {grp_fail} fail in {time.time()-t_start:.0f}s")
        total_ok += grp_ok
        total_fail += grp_fail
        try: local_oracle.unlink()
        except: pass

    overall.close()
    print(f"\n[*] FINISHED. Recovered: {total_ok}  |  Failed: {total_fail}")
    print(f"[*] Output: {output}")
    print(f"[i] Tip: verify integrity with verify-recovered.py {output}")


if __name__ == "__main__":
    main()
