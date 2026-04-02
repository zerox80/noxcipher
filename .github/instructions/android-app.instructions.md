---
description: "Use when working on the NoxCipher Android app. Enforces checking the VeraCrypt reference implementation."
applyTo: ["app/src/**/*.java", "app/src/**/*.kt", "app/src/**/*.xml"]
---

# NoxCipher Android App Code Rules

- **Reference VeraCrypt:** When working on the NoxCipher Android app, you MUST ALWAYS consult the original VeraCrypt source code located in `C:\Daten2\VeraCrypt`. Use it as the source of truth for implementation details.
- **Read-Only Reference:** The `C:\Daten2\VeraCrypt` directory must be treated as strictly read-only. Never attempt to modify any files within that directory.
- **Project Context:** Remember that NoxCipher is the Android application implementation of this software.
