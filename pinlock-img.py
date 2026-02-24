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
ALLOWED_EXTS = {".png"}  # Auth tag stored in PNG metadata safely
PBKDF2_ITERATIONS = 200_000
SALT = b"pinlock-img-v8"
LOCK_SUFFIX = ".lock"
AUTH_FIELD = "pinlock_auth"


# ----------------------------
# Key Derivation
# ----------------------------
def derive_keys(password: str):
    """Derives a seed for XOR and a key for HMAC verification."""
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        SALT,
        PBKDF2_ITERATIONS
    )
    # Split the 32-byte key: 16 bytes for XOR seed, 16 bytes for HMAC
    xor_seed = int.from_bytes(key[:16], "big")
    auth_key = key[16:]
    return xor_seed, auth_key


# ----------------------------
# XOR Transform
# ----------------------------
def xor_transform(array: np.ndarray, seed: int) -> np.ndarray:
    """Generates a deterministic random stream to XOR against image data."""
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
    new_stem = fp.stem[:-len(LOCK_SUFFIX)]
    return fp.with_name(new_stem + fp.suffix)


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
            original_array = np.asarray(img)

            # ------------------------
            # DECRYPT (with Authentication)
            # ------------------------
            if locked:
                stored_tag = img.info.get(AUTH_FIELD)
                if not stored_tag:
                    print(f"❌ No authentication tag found: {fp.name}")
                    return False, None

                # Calculate expected HMAC from the encrypted data on disk
                expected_tag = hmac.new(
                    auth_key,
                    original_array.tobytes(),
                    hashlib.sha256
                ).hexdigest()

                if not hmac.compare_digest(stored_tag, expected_tag):
                    print(f"❌ Wrong password (authentication failed): {fp.name}")
                    return False, None

                transformed = xor_transform(original_array, xor_seed)
                result = Image.fromarray(transformed, mode=mode)

            # ------------------------
            # ENCRYPT (with Tag Generation)
            # ------------------------
            else:
                transformed = xor_transform(original_array, xor_seed)
                result = Image.fromarray(transformed, mode=mode)

                # Generate HMAC tag from the newly encrypted data
                tag = hmac.new(
                    auth_key,
                    transformed.tobytes(),
                    hashlib.sha256
                ).hexdigest()

                meta = PngImagePlugin.PngInfo()
                meta.add_text(AUTH_FIELD, tag)

        # Atomic save using temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = Path(tmp.name)

        if locked:
            result.save(tmp_path, format="PNG")
        else:
            result.save(tmp_path, format="PNG", pnginfo=meta)

        shutil.move(str(tmp_path), str(fp))

        # Rename to indicate locked/unlocked state
        new_path = remove_lock_suffix(fp) if locked else add_lock_suffix(fp)
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
    
    # Restrict to PNG files for metadata reliability
    files = list(path_input.rglob("*.png")) if path_input.is_dir() else [path_input]

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

    enc_count, dec_count, total = 0, 0, 0

    for f in files:
        if f.suffix.lower() in ALLOWED_EXTS:
            success, action = process_img(f, xor_seed, auth_key, dry_run)
            if success:
                total += 1
                if action == "Encrypt": enc_count += 1
                else: dec_count += 1

    print("\n" + "=" * 40 + "\n📊 Batch Summary\n" + "=" * 40)
    print(f"Total Files Handled : {total}")
    print(f"Encrypted           : {enc_count}")
    print(f"Decrypted           : {dec_count}")
    print("=" * 40 + "\n✨ Done!\n")


if __name__ == "__main__":
    main()
