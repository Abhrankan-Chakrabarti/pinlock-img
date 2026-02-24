#!/usr/bin/env python3

import sys
import hashlib
import hmac
import getpass
import shutil
import tempfile
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin


# ----------------------------
# Configuration
# ----------------------------
ALLOWED_EXTS = {".png"}
PBKDF2_ITERATIONS = 200_000
SALT = b"pinlock-img-v9"
LOCK_SUFFIX = ".lock"
AUTH_FIELD = "pinlock_auth"


# ----------------------------
# Key Derivation
# ----------------------------
def derive_keys(password: str):
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        SALT,
        PBKDF2_ITERATIONS,
    )
    xor_seed = int.from_bytes(key[:16], "big")
    auth_key = key[16:]
    return xor_seed, auth_key


# ----------------------------
# XOR Transform
# ----------------------------
def xor_transform(array: np.ndarray, seed: int) -> np.ndarray:
    rng = np.random.default_rng(seed)
    stream = rng.integers(0, 256, size=array.shape, dtype=array.dtype)
    return array ^ stream


# ----------------------------
# Lock Helpers
# ----------------------------
def is_locked_file(fp: Path) -> bool:
    return fp.stem.endswith(LOCK_SUFFIX)


def add_lock_suffix(fp: Path) -> Path:
    return fp.with_name(fp.stem + LOCK_SUFFIX + fp.suffix)


def remove_lock_suffix(fp: Path) -> Path:
    return fp.with_name(fp.stem[:-len(LOCK_SUFFIX)] + fp.suffix)


# ----------------------------
# Authentication Helpers
# ----------------------------
def compute_tag(auth_key: bytes, data: bytes) -> str:
    return hmac.new(auth_key, data, hashlib.sha256).hexdigest()


def verify_tag(auth_key: bytes, data: bytes, stored_tag: str) -> bool:
    expected = compute_tag(auth_key, data)
    return hmac.compare_digest(expected, stored_tag)


# ----------------------------
# Image Processing
# ----------------------------
def process_img(fp: Path, xor_seed, auth_key, dry_run):
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
            pixel_array = np.asarray(img)
            stored_tag = img.info.get(AUTH_FIELD)

        # ----------------------------
        # DECRYPT
        # ----------------------------
        if locked:
            if not stored_tag:
                print(f"❌ Missing authentication tag: {fp.name}")
                return False, None

            if not verify_tag(auth_key, pixel_array.tobytes(), stored_tag):
                print(f"❌ Wrong password (authentication failed): {fp.name}")
                return False, None

            transformed = xor_transform(pixel_array, xor_seed)
            result = Image.fromarray(transformed, mode=mode)

        # ----------------------------
        # ENCRYPT
        # ----------------------------
        else:
            transformed = xor_transform(pixel_array, xor_seed)
            result = Image.fromarray(transformed, mode=mode)

            tag = compute_tag(auth_key, transformed.tobytes())
            meta = PngImagePlugin.PngInfo()
            meta.add_text(AUTH_FIELD, tag)

        # ----------------------------
        # Atomic Save
        # ----------------------------
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        if locked:
            result.save(tmp_path, format="PNG")
        else:
            result.save(tmp_path, format="PNG", pnginfo=meta)

        shutil.move(str(tmp_path), str(fp))

        new_path = remove_lock_suffix(fp) if locked else add_lock_suffix(fp)
        fp.rename(new_path)

        print(f"✅ {action}ed: {new_path.name}")
        return True, action

    except Exception as e:
        print(f"❌ Error on {fp.name}: {e}")
        return False, None


# ----------------------------
# Main
# ----------------------------
def main():
    path_input = Path(
        sys.argv[1] if len(sys.argv) > 1 else input("Path: ").strip()
    )

    if not path_input.exists():
        print("❌ Path does not exist.")
        return

    dry_run = input("Dry Run? (y/n): ").strip().lower() == "y"

    if path_input.is_dir():
        files = list(path_input.rglob("*.png"))
    else:
        if path_input.suffix.lower() not in ALLOWED_EXTS:
            print("❌ Only PNG files are supported.")
            return
        files = [path_input]

    xor_seed = None
    auth_key = None

    if not dry_run:
        encrypting_exists = any(not is_locked_file(f) for f in files)

        pwd = getpass.getpass("Password: ")
        if not pwd:
            print("❌ Password cannot be empty.")
            return

        if encrypting_exists:
            if getpass.getpass("Confirm Password: ") != pwd:
                print("❌ Passwords do not match.")
                return

        print("⚙️  Deriving secure keys...")
        xor_seed, auth_key = derive_keys(pwd)

    enc_count = 0
    dec_count = 0
    total = 0

    for f in files:
        success, action = process_img(f, xor_seed, auth_key, dry_run)
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