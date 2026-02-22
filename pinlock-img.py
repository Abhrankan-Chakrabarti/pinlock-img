#!/usr/bin/env python3

import sys
import hashlib
import getpass
import shutil
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image


# ----------------------------
# Configuration
# ----------------------------
ALLOWED_EXTS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".ico"}
PBKDF2_ITERATIONS = 200_000
SALT = b"pinlock-img-v7"
LOCK_SUFFIX = ".lock"


# ----------------------------
# XOR Transform
# ----------------------------
def xor_transform(array: np.ndarray, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    stream = rng.integers(0, 256, size=array.shape, dtype=array.dtype)
    return array ^ stream


# ----------------------------
# Lock State Helpers
# ----------------------------
def is_locked_file(fp: Path) -> bool:
    return fp.stem.endswith(LOCK_SUFFIX)


def add_lock_suffix(fp: Path) -> Path:
    if is_locked_file(fp):
        return fp
    return fp.with_name(fp.stem + LOCK_SUFFIX + fp.suffix)


def remove_lock_suffix(fp: Path) -> Path:
    if is_locked_file(fp):
        new_stem = fp.stem[:-len(LOCK_SUFFIX)]
        return fp.with_name(new_stem + fp.suffix)
    return fp


# ----------------------------
# Image Processing
# ----------------------------
def process_img(fp: Path, seed: int | None, dry_run: bool):
    try:
        locked = is_locked_file(fp)
        action = "Decrypt" if locked else "Encrypt"

        if dry_run:
            state = "LOCKED" if locked else "CLEAN"
            print(f"🔍 [{state}] Would {action}: {fp.name}")
            return True, action

        with Image.open(fp) as img:
            img.load()
            mode = img.mode
            fmt = img.format or fp.suffix.replace(".", "").upper()
            original_array = np.asarray(img)
            palette = img.getpalette()

        transformed = xor_transform(original_array, seed)
        result = Image.fromarray(transformed, mode=mode)

        if mode == "P" and palette:
            result.putpalette(palette)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        result.save(tmp_path, format=fmt)
        shutil.move(str(tmp_path), str(fp))

        new_path = remove_lock_suffix(fp) if locked else add_lock_suffix(fp)
        if new_path != fp:
            fp.rename(new_path)

        print(f"✅ {action}ed: {new_path.name}")
        return True, action

    except Exception as e:
        print(f"❌ Error on {fp.name}: {e}")
        return False, None


# ----------------------------
# Main Entrance
# ----------------------------
def main():
    path_input = Path(
        sys.argv[1] if len(sys.argv) > 1 else input("Path: ").strip()
    )

    if not path_input.exists():
        print("❌ Path does not exist.")
        return

    dry_run = input("Dry Run? (y/n): ").strip().lower() == "y"
    files = list(path_input.rglob("*")) if path_input.is_dir() else [path_input]
    seed = None

    if not dry_run:
        encrypting_exists = any(
            f.suffix.lower() in ALLOWED_EXTS and not is_locked_file(f)
            for f in files
        )

        pwd = getpass.getpass("Password: ")
        if not pwd:
            print("❌ Password cannot be empty.")
            return

        if encrypting_exists:
            if getpass.getpass("Confirm Password: ") != pwd:
                print("❌ Passwords do not match.")
                return

        print("⚙️  Deriving secure key (PBKDF2)...")
        key = hashlib.pbkdf2_hmac(
            "sha256",
            pwd.encode(),
            SALT,
            PBKDF2_ITERATIONS
        )
        seed = int.from_bytes(key[:8], "big")

    enc_count = 0
    dec_count = 0
    total = 0

    for f in files:
        if f.suffix.lower() in ALLOWED_EXTS:
            success, action = process_img(f, seed, dry_run)
            if success:
                total += 1
                if action == "Encrypt":
                    enc_count += 1
                elif action == "Decrypt":
                    dec_count += 1

    print("\n" + "=" * 40)
    print("📊 Batch Summary")
    print("=" * 40)
    print(f"Total Files Handled : {total}")
    print(f"Encrypted           : {enc_count}")
    print(f"Decrypted           : {dec_count}")
    print("=" * 40)
    print("✨ Done!\n")


if __name__ == "__main__":
    main()