import hashlib
import json
import os
from datetime import datetime, timezone

# Purpose: Defines how evidence entries are structured and 
# how the full audit trail is managed.
# Every time a file is logged, a new Block is created and linked to the
# previous one.

class Block:
    """
    Represents a single evidence entry in the chain.

    Each block contains: what file was submitted, who submitted it, when,
    and a cryptographic link back to the block before it. Changing any of
    these fields after the fact will produce a different hash, thus highlighting
    tampering.
    """

    def __init__(self, index, file_name, file_hash, submitted_by, previous_hash):
        self.index = index # Position
        self.timestamp = datetime.now(timezone.utc).isoformat() # UTC timestamp at time of logging
        self.file_name = file_name # Original filename e.g. "photo.jpg"
        self.file_hash = file_hash # SHA-256 fingerprint of the file
        self.submitted_by = submitted_by # Who logged this evidence
        self.previous_hash = previous_hash # Links this block to prev
        self.hash = self.compute_hash() # This block's fingerprint

    def compute_hash(self):
        """
        Produces a unique fingerprint for this block by hashing all its fields together.

        The fingerprint changes if even one character in any field is modified. This is 
        what makes tampering detectable.
        """
        block_string = (
            str(self.index) +
            self.timestamp +
            self.file_name +
            self.file_hash +
            self.submitted_by +
            self.previous_hash
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        """
        Converts this block into a plain dictionary so to save to JSON.
        All fields are included — nothing is omitted from the audit trail.
        """
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "file_name": self.file_name,
            "file_hash": self.file_hash,
            "submitted_by": self.submitted_by,
            "previous_hash": self.previous_hash,
            "hash": self.hash
        }


class Chain:
    """
    Manages the full sequence of evidence blocks.

    Handles adding new entries, validating the chain's integrity,
    and persisting everything to disk between sessions.
    """

    def __init__(self):
        self.blocks = []
        self.chain_file = "evidence_log.json"

        self.load()

        # Create chain if none found
        if len(self.blocks) == 0:
            self.create_genesis_block()

    def create_genesis_block(self):
        """
        Creates block #0 aka genesis block.

        Gives first real block something to reference as its previous hash.
        """
        genesis = Block(
            index=0,
            file_name="GENESIS",
            file_hash="0",
            submitted_by="SYSTEM",
            previous_hash="0"
        )
        self.blocks.append(genesis)
        self.save()

    def add_block(self, file_name, file_hash, submitted_by):
        """
        Logs a new piece of evidence by appending a block to the chain.

        Grabs the last block's hash and passes it in as the new block's
        previous_hash. Returns the new block so caller can confirm 
        what was logged.
        """
        last_block = self.blocks[-1]

        new_block = Block(
            index= last_block.index + 1,
            file_name=file_name,
            file_hash=file_hash,
            submitted_by= submitted_by,
            previous_hash=last_block.hash
        )

        self.blocks.append(new_block)
        self.save()
        return new_block

    def is_valid(self):
        """
        Searches the entire chain and checks for signs of tampering.

        2 checks on every block (skipping genesis):
          1. Does the block's stored hash still match a fresh recomputation?
             If not, someone edited the block's data after it was created.
          2. Does the block's previous_hash match the actual hash of the block before it?
             If not, the chain has been broken or reordered.

        Returns True if everything looks intact, False if anything is off.
        """
        for i in range(1, len(self.blocks)):
            current = self.blocks[i]
            previous = self.blocks[i - 1]

            if current.hash != current.compute_hash():
                return False  # Block data was modified after logging

            if current.previous_hash != previous.hash:
                return False  # Chain link is broken

        return True

    def find_by_hash(self, file_hash):
        """
        Looks up a block by its file hash.

        Used during verification — rehash the file and search for a match.
        If found, the file was logged and hasn't been modified since.
        Returns the matching block, or None if no match exists.
        """
        for block in self.blocks:
            if block.file_hash == file_hash:
                return block
        return None

    def save(self):
        """
        Writes the current chain to evidence_log.json.

        Called automatically after every new block is added,
        so the log on disk is always up to date.
        """
        all_blocks = [block.to_dict() for block in self.blocks]

        with open(self.chain_file, "w") as f:
            json.dump(all_blocks, f, indent=2)

    def load(self):
        """
        Reads a previously saved chain from evidence_log.json, if it exists.

        Rebuilds each Block object from the stored data.
        """
        if not os.path.exists(self.chain_file):
            return

        with open(self.chain_file, "r") as f:
            data = json.load(f)

        for item in data:
            block = Block(
                index=item["index"],
                file_name=item["file_name"],
                file_hash=item["file_hash"],
                submitted_by=item["submitted_by"],
                previous_hash=item["previous_hash"]
            )
            block.timestamp = item["timestamp"]
            block.hash = item["hash"]
            self.blocks.append(block)