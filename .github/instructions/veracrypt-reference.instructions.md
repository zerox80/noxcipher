---
description: "Use when modifying Noxcipher encryption, decryption, or volume handling logic. Enforces checking the original VeraCrypt C/C++ source code for reference."
applyTo: ["**/*.kt", "**/*.rs"]
---
# VeraCrypt Reference Guidelines

When implementing or bugfixing features in Noxcipher, the primary goal is to match the behavior of the original VeraCrypt implementation exactly.

## Rules

1. **Check Original Source:** Before making logical changes to volume mounting, header parsing, or encryption/decryption in Noxcipher, always read the corresponding C/C++ source code in the `C:\Daten2\VeraCrypt` workspace.
2. **Read-Only Access:** You must only *read* the VeraCrypt repository. Never modify the VeraCrypt code.
3. **Match Logic:** Ensure the Kotlin and Rust implementations in Noxcipher strictly follow the exact same algorithms, byte offsets, buffer handling, and edge-case logic as the original VeraCrypt codebase.

## Key VeraCrypt Reference Directories
- **Cryptography & Algorithms:** `C:\Daten2\VeraCrypt\src\Crypto\`
- **Volume Header & Formats:** `C:\Daten2\VeraCrypt\src\Volume\`
- **Mounting & UI Logic:** `C:\Daten2\VeraCrypt\src\Mount\`
- **Device & Sector Handling:** `C:\Daten2\VeraCrypt\src\Driver\`
