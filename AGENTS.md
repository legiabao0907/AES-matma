# AES Cryptography Demo — Agent Guidelines

## Project Overview
Educational AES-128 block cipher implementation and Padding Oracle Attack demonstration (HUST university project). Two standalone JavaScript files — no build system, no package manager.

## How to Run

```bash
# Run the Padding Oracle Attack demo
node padding_oracle_demo.js
```

`aes128.js` is a plain JS class (no Node.js dependencies) — import or copy-paste to use `AES128.encryptBlock(plaintext, key)`.

## Architecture

| File | Role | Dependencies |
|---|---|---|
| `aes128.js` | AES-128 class: S-Box, Key Expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, 10-round encrypt | None (pure JS) |
| `padding_oracle_demo.js` | VictimServer (AES-128-CBC via `crypto`) + brute-force Padding Oracle attacker | Node.js `crypto` |

## Conventions
- **Vietnamese comments** throughout — code sections are labeled with author names (An, Bảo) and section headers like `// PHẦN 1: ĐÓNG GÓP CỦA AN`
- **Educational tone**: detailed inline explanations of each AES step (Confusion, Diffusion, GF(2⁸) multiplication)
- No tests, no linting, no CI — this is a pure demo/learning project

## Scope
**Do NOT use these implementations for production encryption.** This is educational code for understanding AES internals and the Padding Oracle vulnerability. Use standard libraries (Node.js `crypto`, Web Crypto API) for real cryptographic operations.
