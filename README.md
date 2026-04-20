# EvidenceLog

> "Digital evidence is only as trustworthy as its chain of custody."

That line stuck with me. And it's the entire reason this project exists.

---

## 🧠 The Idea

I was reading about how law enforcement agencies handle digital evidence — images, videos, audio recordings — and a pattern kept coming up: the evidence itself was fine, but the *handling* of it wasn't. Files get passed between analysts, copied across machines, uploaded and downloaded. Somewhere in that chain, something changes. And when it does, there's often no way to prove it.

So I asked: what's the simplest possible system that guarantees you'd always know?

The answer is a blockchain. Not the crypto kind — the core concept. A chain of cryptographic links where tampering with anything, anywhere, breaks everything after it. Silent modification becomes mathematically impossible to hide.

So I built it.

---

## 🎯 What EvidenceLog Does

- Generates a SHA-256 fingerprint for any file — image, PDF, video, anything
- Logs it to a tamper-proof chain with submitter name and timestamp
- Lets you verify any file against the chain at any time
- Detects tampering instantly — in the file *or* in the chain itself

---

## 💥 The Part That Makes It Interesting

The core insight is deceptively simple:

**You don't need to store the file. You just need its fingerprint.**

SHA-256 produces a unique 64-character hash for every file. Change a single pixel in an image, one word in a document, one frame in a video — the hash is completely different. And because each block in the chain stores the hash of the block before it, you can't go back and quietly edit old records either. The math catches it.

---

## 📊 Project Structure

```
EvidenceLog/
├── main.py           # Entry point — three commands cover the full workflow
├── blockchain.py         # Block and Chain logic — the core of the system
├── hasher.py    # SHA-256 file hashing
└── README.md
```

---

## 🚀 Run It Yourself

```bash
git clone https://github.com/yourusername/EvidenceLog
cd EvidenceLog
python main.py add        # Log a file
python main.py verify     # Verify a file's integrity
python main.py view       # View the full audit trail
```

No installs. No dependencies. Pure Python.

---

## 🔍 How Tamper Detection Works

| Scenario | What Happens |
|---|---|
| File logged, never modified | Verify → match found ✓ |
| File modified after logging | Verify → hash mismatch, not found ✗ |
| Block edited directly in JSON | Chain integrity check fails ✗ |
| Blocks reordered or deleted | Previous hash mismatch detected ✗ |

---

## 🛠️ Tech Stack

```
hashlib     # SHA-256 cryptographic hashing
json        # Chain persistence
datetime    # Tamper-evident timestamps
os          # File handling
```

All built-in. Nothing to install.

---
Manal Khan UWaterloo, 2026
