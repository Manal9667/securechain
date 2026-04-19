import os
import sys

from hasher import hash_file
from blockchain import Chain

# main.py
# Purpose: The entry point for Securechain. Reads the command provided
# by the user and routes it to the appropriate function. Keeps the interface
# simple — three commands cover the full evidence workflow.
#
# Usage:
#   python main.py add -- log a new file on the chain
#   python main.py verify -- check if a file is on the chain
#   python main.py view -- print the full audit trail


def cmd_add(chain):
    """
    Logs a new file as evidence on the chain.

    Prompts for a file path and submitter name, computes the file's
    SHA-256 fingerprint, and appends a new block to the chain.
    The file itself is never stored — only its hash and metadata.
    """
    print("\n--- ADD EVIDENCE ---\n")

    file_path = input("Enter the file path: ").strip()

    if not os.path.isfile(file_path):
        print("Error: file not found.")
        return

    submitter = input("Your name: ").strip()

    # Strip the directory path — we only store the filename itself
    file_name = os.path.basename(file_path)

    print("Hashing file...")
    file_hash = hash_file(file_path)

    new_block = chain.add_block(file_name, file_hash, submitter)

    print(f"\nEvidence logged in block #{new_block.index}")
    print(f"Hash: {file_hash}")


def cmd_verify(chain):
    """
    Verifies whether a file has been tampered with since it was logged.

    Rehashes the file and searches the chain for a matching fingerprint.
    If the file has been modified in any way since logging, the hash will
    differ and no match will be found. Also runs a full chain integrity
    check to confirm the audit trail itself hasn't been altered.
    """
    print("\n--- VERIFY EVIDENCE ---\n")

    file_path = input("Enter the file path to verify: ").strip()

    if not os.path.isfile(file_path):
        print("Error: file not found.")
        return

    print("Hashing file...")
    file_hash = hash_file(file_path)
    print(f"Hash: {file_hash}")

    block = chain.find_by_hash(file_hash)

    if block is not None:
        print(f"\nVerified — found on chain (block #{block.index})")
        print(f"Logged by {block.submitted_by} at {block.timestamp}")
    else:
        print("\nNot found. This file was either never logged or has been modified.")

    print()

    if chain.is_valid():
        print("Chain integrity: VALID — no tampering detected")
    else:
        print("Chain integrity: INVALID — the chain has been modified")


def cmd_view(chain):
    """
    Prints the full evidence log — every block in the chain.

    Displays all metadata for each entry including file name, submitter,
    timestamp, and cryptographic hashes. Also runs a final integrity check
    across the entire chain and reports the result at the bottom.
    """
    print("\n--- EVIDENCE LOG ---\n")
    print(f"Total entries: {len(chain.blocks) - 1}\n")  # Subtract genesis block

    for block in chain.blocks:
        print("=" * 55)
        if block.index == 0:
            print("Block #0 — Genesis (chain origin)")
        else:
            print(f"Block #{block.index}")
            print(f"  File:       {block.file_name}")
            print(f"  Submitted:  {block.submitted_by}")
            print(f"  Time:       {block.timestamp}")
            print(f"  File hash:  {block.file_hash}")
            print(f"  Block hash: {block.hash}")
            print(f"  Prev hash:  {block.previous_hash}")

    print("=" * 55)
    print()

    if chain.is_valid():
        print("Chain integrity: VALID")
    else:
        print("Chain integrity: INVALID — tampering detected")


# --- Entry point ---

if len(sys.argv) < 2:
    print("Usage: python main.py <command>")
    print("Commands: add, verify, view")
    sys.exit(1)

command = sys.argv[1]
chain = Chain()

if command == "add":
    cmd_add(chain)
elif command == "verify":
    cmd_verify(chain)
elif command == "view":
    cmd_view(chain)
else:
    print(f"Unknown command: '{command}'")
    print("Commands: add, verify, view")