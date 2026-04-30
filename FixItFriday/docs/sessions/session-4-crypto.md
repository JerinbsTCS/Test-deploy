# Insecure Cryptography

**Date:** April 24, 2026
**Vulnerability:** Use of a Broken or Risky Cryptographic Algorithm (CWE-327), Inadequate Encryption Strength (CWE-326)  
**OWASP Category:** [A04:2025 – Cryptographic Failures](../reference/owasp-top-10.md)

---

## What Was Demonstrated

In this session, we explored **Insecure Cryptography** by simulating the **2013 Adobe breach** — where 153 million user passwords were encrypted with ECB mode, allowing attackers to deduce passwords without ever decrypting them.

We built a Spring Boot app with an H2 database containing users with:

- **Passwords encrypted using `Cipher.getInstance("AES")`** — which defaults to AES/ECB/PKCS5Padding
- **Password hints stored in plaintext** alongside the encrypted passwords

The attack: ECB is deterministic — identical passwords produce identical ciphertext. An attacker groups users by ciphertext, cross-references their plaintext hints, and deduces passwords **without knowing the key**.

### The Real-World Finding

This is the actual code pattern flagged by Semgrep in production:

```java
import javax.crypto.Cipher;

private String encryptForDPS(String dataToEncrpt) {
    logger.debug("Enter encryptForDPS(): dataToEncrypt: {}", dataToEncrpt);
    Key key = generateKeyForEParcelURL();
    ByteArrayOutputStream encVal = new ByteArrayOutputStream();
    try {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        encVal.write(cipher.doFinal(dataToEncrpt.getBytes()));
    } catch (Exception e2) {
        logger.error(e2.getMessage());
    }
    logger.debug("Exit encryptForDPS()");
    return Base64.getEncoder().encodeToString(encVal.toByteArray());
}
```

!!! danger "Problem"
    `Cipher.getInstance("AES")` without specifying a mode defaults to **AES/ECB/PKCS5Padding**. ECB mode encrypts each 16-byte block independently — identical inputs always produce identical outputs. There is no IV and no authentication tag. This is the same class of weakness that enabled the Adobe breach.

---

## Resources

### :material-docker: Container Images

```bash
# Pull and run the app
docker pull ghcr.io/<owner>/<repo>/fixitfriday/session-4-insecurecrypto:latest
docker run -p 8080:8080 ghcr.io/<owner>/<repo>/fixitfriday/session-4-insecurecrypto:latest
```

### :material-github: Source Code

- **Session-4-InsecureCrypto** — Spring Boot app simulating the Adobe breach with vulnerable (ECB) and secure (GCM) encryption

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/users` | GET | View the leaked database — emails, encrypted passwords, plaintext hints |
| `/api/breach/analyze` | GET | **The Adobe attack** — groups users by ciphertext, shows hints for deduction |
| `/api/breach/fix` | POST | **Remediation** — re-encrypts all passwords from ECB to GCM |
| `/api/demo/ecb-vs-gcm` | GET | Side-by-side comparison: ECB deterministic vs GCM randomized |
| `/api/crypto/unsafe/encrypt` | POST | Encrypt with AES/ECB (vulnerable) |
| `/api/crypto/unsafe/decrypt` | POST | Decrypt AES/ECB ciphertext |
| `/api/crypto/safe/encrypt` | POST | Encrypt with AES/GCM (secure) |
| `/api/crypto/safe/decrypt` | POST | Decrypt AES/GCM ciphertext |

---

## Vulnerability Details

### Seed Data — The "Adobe Database"

The app seeds 19 users at startup. Many share common passwords, each with a plaintext hint:

| Password | Users | Sample Hints |
|----------|-------|-------------|
| `123456` | 4 | "ascending numbers", "first six digits", "one two three four five six" |
| `password` | 3 | "the word itself", "what you type to login", "p-a-s-s-w-o-r-d" |
| `qwerty` | 2 | "keyboard row", "top left keys" |
| `iloveyou` | 2 | "romantic phrase", "three words, no spaces" |
| `dragon` | 2 | "mythical beast", "fire-breathing creature" |
| Various unique | 5 | Individual hints |
| CTF flag | 1 | "the challenge reward" |

### Vulnerable Code

The `DataSeeder` encrypts all passwords using ECB at startup:

```java
private void seed(String email, String password, String hint) {
    User user = new User();
    user.setEmail(email);
    user.setEncryptedPassword(cryptoService.encryptECB(password));
    user.setPasswordHint(hint);
    userRepository.save(user);
}
```

The encryption uses the exact Semgrep finding pattern:

```java
public String encryptECB(String plaintext) {
    try {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        ByteArrayOutputStream encVal = new ByteArrayOutputStream();
        encVal.write(cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8)));
        return Base64.getEncoder().encodeToString(encVal.toByteArray());
    } catch (Exception e) {
        return "Error: " + e.getMessage();
    }
}
```

### Exploitation

#### 1. View the Leaked Database

```bash
curl http://localhost:8080/api/users | python -m json.tool
```

You see emails, encrypted passwords, and plaintext hints. Notice that **multiple users share the same encrypted password value**.

#### 2. The Adobe Attack — Analyze the Breach

```bash
curl http://localhost:8080/api/breach/analyze | python -m json.tool
```

This groups users by their encrypted password. Because ECB is deterministic, all 4 users with password "123456" have the **exact same ciphertext**. Cross-reference their hints:

- "ascending numbers"
- "first six digits"  
- "one two three four five six"
- "keyboard top row numbers"

The password is obviously **123456** — deduced without any decryption, without the key.

!!! example "Adobe Breach in Action"
    ```
    Encrypted Password: "EQ7fIpT7i/Q="  ← same for all 4 users
    ├── john.smith@example.com    → hint: "ascending numbers"
    ├── sarah.jones@example.com   → hint: "first six digits"
    ├── mike.chen@example.com     → hint: "one two three four five six"
    └── lisa.wang@example.com     → hint: "keyboard top row numbers"

    Deduced password: 123456 ✓ (no key needed!)
    ```

#### 3. CTF — Extract the Flag

```bash
# Step 1: Find the ctf user's encrypted password from /api/users
curl http://localhost:8080/api/users | python -m json.tool

# Step 2: Decrypt it using the unsafe endpoint
curl -X POST http://localhost:8080/api/crypto/unsafe/decrypt \
  -H "Content-Type: application/json" \
  -d '{"data": "<paste encrypted_password from ctf@adobe-sim.com>"}'
```

#### 4. ECB vs GCM — Side-by-Side

```bash
curl http://localhost:8080/api/demo/ecb-vs-gcm | python -m json.tool
```

Encrypts "123456" three times with each method:

- **ECB**: All three ciphertexts are identical
- **GCM**: All three ciphertexts are different

---

### Secure Code

Uses **AES/GCM/NoPadding** with a random 12-byte IV prepended to the ciphertext:

```java
public String encryptGCM(String plaintext) {
    try {
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, iv));

        byte[] encrypted = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext: [IV (12 bytes) | ciphertext + auth tag]
        byte[] combined = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

        return Base64.getEncoder().encodeToString(combined);
    } catch (Exception e) {
        return "Error: " + e.getMessage();
    }
}
```

!!! success "Fix"
    - **AES/GCM/NoPadding** — Authenticated encryption with associated data (AEAD)
    - **Random 12-byte IV** — Every encryption produces different ciphertext, even for the same plaintext
    - **128-bit authentication tag** — Detects any tampering with the ciphertext
    - **IV prepended to ciphertext** — The receiver extracts the IV before decrypting

### Verification — Apply the Fix Live

```bash
# Re-encrypt all passwords from ECB → GCM
curl -X POST http://localhost:8080/api/breach/fix | python -m json.tool
```

Response:

```json
{
    "status": "Re-encrypted all passwords from AES/ECB to AES/GCM/NoPadding",
    "users_updated": 19,
    "unique_ciphertexts_before": 10,
    "unique_ciphertexts_after": 19
}
```

Before: 10 unique ciphertexts for 19 users (grouping reveals shared passwords).  
After: 19 unique ciphertexts — **every user now has a different encrypted value**, even those with the same password.

```bash
# Run the breach analysis again — grouping no longer works
curl http://localhost:8080/api/breach/analyze | python -m json.tool
```

Every group now has exactly 1 user. The Adobe attack is neutralized.

---

## ECB vs GCM — Visual Comparison

```
┌─────────────────────────────────────────────────┐
│  AES/ECB (Vulnerable) — The Adobe Problem       │
│                                                 │
│  User A password: "123456" ──→ AES/ECB ──→ "EQ7f│
│  User B password: "123456" ──→ AES/ECB ──→ "EQ7f│
│  User C password: "123456" ──→ AES/ECB ──→ "EQ7f│
│  User D password: "123456" ──→ AES/ECB ──→ "EQ7f│
│                                     ^^^^^^^^^^^^│
│              ALL IDENTICAL — group & cross-hint! │
│                                                 │
│  • No IV — deterministic                        │
│  • No auth tag — tampering undetected           │
│  • Same password = same ciphertext ALWAYS       │
└─────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────┐
│  AES/GCM (Secure) — The Fix                     │
│                                                 │
│  User A password: "123456" ──→ AES/GCM ──→ "a8Kx│
│  User B password: "123456" ──→ AES/GCM ──→ "Tz9Q│
│  User C password: "123456" ──→ AES/GCM ──→ "mN3v│
│  User D password: "123456" ──→ AES/GCM ──→ "pR7w│
│                                     ^^^^^^^^^^^^│
│              ALL DIFFERENT — grouping impossible! │
│                                                 │
│  • Random IV — non-deterministic                │
│  • Auth tag — integrity guaranteed              │
│  • Same password ≠ same ciphertext              │
└─────────────────────────────────────────────────┘
```

---

## Dockerfile

```dockerfile
FROM eclipse-temurin:17-jre
WORKDIR /app

ARG S4_FLAG
ARG S4_SECRET
ENV S4_FLAG=${S4_FLAG}
ENV S4_SECRET=${S4_SECRET}

COPY ./target/*.jar app.jar

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
```

!!! info "Configuration"
    - `S4_FLAG` — The CTF flag injected at build time (stored as the `ctf@adobe-sim.com` user's password)
    - `S4_SECRET` — The AES encryption key (16 bytes for AES-128)
    - Both are passed as environment variables and read via `application.properties`

---

## CTF Flag

| Flag | Location | Attack Vector |
|------|----------|---------------|
| `S4_FLAG` | `ctf@adobe-sim.com` user's encrypted password | Decrypt using `/api/crypto/unsafe/decrypt` |

---

## Real-World Impact — Adobe Breach (2013)

| Fact | Detail |
|------|--------|
| **Users affected** | 153 million |
| **Encryption** | 3DES-ECB (same deterministic weakness as AES-ECB) |
| **What leaked** | Encrypted passwords + plaintext hints |
| **Attack** | Group by ciphertext → cross-reference hints → deduce passwords |
| **Outcome** | Adobe settled for $1.1M, massive reputational damage |

Other incidents with the same root cause:

- **Zoom (2020)** — Video streams encrypted with AES-128 ECB; forced upgrade to GCM
- **Microsoft PPTP** — Deterministic encryption in MS-CHAPv2; protocol deprecated

---

## Key Takeaways

- **Never use `Cipher.getInstance("AES")`** without specifying mode and padding — it defaults to ECB
- **Always specify the full transformation string**: `AES/GCM/NoPadding` (or `AES/CBC/PKCS5Padding` with HMAC)
- **Always use a random IV** — without it, encryption is deterministic and vulnerable to pattern analysis
- **Use authenticated encryption (GCM)** — it provides both confidentiality and integrity in one operation
- ECB doesn't let you decrypt without the key, but it **leaks which records have the same value** — that's enough to break the system when combined with metadata (hints, frequency analysis, known plaintexts)
- Semgrep rules `java.lang.security.audit.crypto.ecb-cipher` and `java.lang.security.audit.crypto.no-static-initialization-vector` catch this pattern
- **Passwords should be hashed (bcrypt/argon2), not encrypted** — but when encryption is required (e.g., reversible tokens), use GCM

---
