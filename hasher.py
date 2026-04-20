import hashlib

# Purpose: Generates a unique SHA-256 fingerprint for any file.
# This is the first step in the evidence logging process — before anything
# gets written to the chain, we need a way to represent the file's
# contents as a fixed-length string. That string is what gets stored and
# later used to verify nothing has changed.


def hash_file(file_path):
    """
    Reads a file and returns its SHA-256 hash as a hex string.

    SHA-256 is a one-way function — the same file always produces the same
    hash, but if even a single byte changes, the output is completely different.
    This makes it ideal for tamper detection.

    Files are read in chunks rather than all at once so this works reliably
    on large files (videos, disk images) without running out of memory.

    Returns a 64-character hex string e.g. "3b4c9fa8d1..."
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()