# BUP CSE FEST 2026 CTF Writeups

Writeups, solutions, and supporting materials from the **BUP CSE FEST 2026 CTF Preliminary Round**.

The repository documents the methodology used to solve the challenges, including reconnaissance, vulnerability analysis, exploitation, reverse engineering, and proof-of-concept development.

## 📌 Competition

* **Event:** BUP CSE FEST 2026 CTF
* **Round:** Online Preliminary Round
* **Date:** 19 September 2026
* **Focus:** Capture The Flag / Cybersecurity

---

## 📂 Repository Structure

```text
BUP-CSE-Fest-2026-CTF/
│
├── prelims-rev-reverse404/
│   ├── FLAG.txt
│   ├── walkthrough.md
│   └── walkthrough.pdf
│
├── quay-index/
│   ├── FLAG.txt
│   ├── walkthrough.md
│   └── walkthrough.pdf
│
├── zz-EXAMPLE-ret2win/
│   ├── FLAG.txt
│   ├── walkthrough.md
│   └── walkthrough.pdf
│
└── README.md
```

---

## 🏴 Challenges

### 1. `prelims-rev-reverse404`

**Category:** Reverse Engineering

A reverse-engineering challenge involving a custom input transformation and an encoded 56-byte value stored in the binary.

The solution involved:

* Static analysis of the ELF binary
* String and import enumeration
* Disassembly with `radare2`
* Identifying the input validation loop
* Understanding compiler-generated magic-number division
* Reversing XOR, addition, and bit-rotation operations
* Reconstructing the expected 56-byte input
* Verifying the recovered input against the original algorithm

**Flag:**

```text
[See FLAG.txt]
```

---

### 2. `quay-index`

**Category:** Web

A web exploitation challenge involving a file preview endpoint, path traversal, weak path validation, and forged session authentication.

The solution involved:

* Web application reconnaissance
* Endpoint enumeration
* Analysing the `/preview` functionality
* Identifying a path traversal filter bypass
* Exploiting a flawed `startswith()` path containment check
* Accessing a sibling directory outside the intended document root
* Extracting an HMAC signing key
* Reverse-engineering the session cookie format
* Forging a privileged session
* Accessing the protected cabinet

The primary vulnerabilities were:

```text
Path traversal filter bypass
        ↓
Broken path containment check
        ↓
HMAC signing key disclosure
        ↓
Session forgery
        ↓
Privilege escalation
```

**Flag:**

```text
[See FLAG.txt]
```

---

### 3. `zz-EXAMPLE-ret2win`

**Category:** Pwn / Binary Exploitation

> **Note:** This directory is a worked example rather than an actual competition challenge. It was included as a demonstration of the binary exploitation workflow.

The example demonstrates a classic **ret2win stack buffer overflow**.

Topics covered:

* ELF reconnaissance
* `checksec`
* Stack buffer overflow
* Saved return address overwrite
* Calculating the stack offset
* No canary / No PIE analysis
* `pwntools`
* Return-to-win exploitation

The exploit redirects execution to the existing `win()` function rather than injecting shellcode.

**Flag:**

```text
[See FLAG.txt]
```

---

## 🛠️ Tools Used

The writeups make use of a range of common cybersecurity and CTF tools:

### Reverse Engineering

* `radare2`
* `rabin2`
* `strings`
* `gdb`
* Python

### Web Security

* `curl`
* Python
* HTTP request analysis
* Web endpoint enumeration

### Binary Exploitation

* `pwntools`
* `gdb`
* `checksec`
* Python

---

## 🧠 Skills Practiced

The challenges covered several practical cybersecurity concepts:

```text
Reverse Engineering
        │
        ├── ELF Analysis
        ├── Disassembly
        ├── Input Validation Analysis
        └── Cryptographic/Bitwise Transformation Reversal

Web Security
        │
        ├── Endpoint Reconnaissance
        ├── Path Traversal
        ├── Broken Access Control
        ├── HMAC Analysis
        └── Session Forgery

Binary Exploitation
        │
        ├── Stack Buffer Overflow
        ├── checksec
        ├── Return Address Control
        └── ret2win
```

---

## 📖 Writeup Philosophy

Each writeup attempts to document more than just the final flag.

The goal is to explain:

1. What was initially observed
2. How the target was enumerated
3. Which hypotheses were tested
4. How the vulnerability or weakness was identified
5. Why the exploitation technique worked
6. How the flag was obtained
7. What security concept can be learned from the challenge

This makes the repository useful as a reference for future CTFs and cybersecurity practice.

---

## ⚠️ Disclaimer

All techniques and exploits documented in this repository were performed in the context of CTF challenges and intentionally vulnerable environments.

They are provided for **educational and cybersecurity research purposes**. Do not apply these techniques to systems or applications without explicit authorization.

---

## 📜 Event

**BUP CSE FEST 2026 CTF**
Online Preliminary Round
19 September 2026

---

⭐ If you find the writeups useful, consider starring the repository.
