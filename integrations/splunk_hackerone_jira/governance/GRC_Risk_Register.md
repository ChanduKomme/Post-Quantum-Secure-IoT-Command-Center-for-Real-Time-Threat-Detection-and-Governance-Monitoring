# GRC Risk Register — PQC IoT Real Working Model

**Project:** PQC IoT Real Working Model  
**Platform:** BL602 / PineCone (Bouffalo Lab)  
**Cryptography:** ML-KEM-512, HKDF-SHA-256, AES-128-CCM  
**Protocol:** CoAP over UDP port 5683  
**Last Updated:** 2026-03-26  
**Overall Posture:** ✅ ACCEPTABLE — Zero high residual risks

---

## Executive Summary

| Metric | Value |
|---|---|
| Total risks assessed | 10 |
| High residual risks | **0** ✅ |
| Medium residual risks | 6 |
| Low residual risks | 4 |
| Controls fully implemented | 7 / 10 (70%) |
| Controls partially implemented | 3 / 10 (30%) |
| Compliance score | **70%** |

All critical and high inherent risks have been brought down to medium or low through implemented controls. Three risks are accepted with partial controls pending further hardware security hardening.

---

## Risk Register

### R-001 — Replay Attack
- **Category:** Protocol Security
- **Inherent Risk:** High
- **Residual Risk:** Medium
- **Control:** 32-slot nonce cache on Receiver rejects duplicate nonces within session window
- **Status:** Mitigated ✅

### R-002 — AEAD Authentication Failure
- **Category:** Cryptographic Integrity
- **Inherent Risk:** High
- **Residual Risk:** Medium
- **Control:** AES-128-CCM with 16-byte authentication tag — any single-bit flip fails verification
- **Status:** Mitigated ✅

### R-003 — ML-KEM Public Key Substitution (MITM)
- **Category:** Key Management
- **Inherent Risk:** High (Critical Impact)
- **Residual Risk:** Low
- **Control:** SHA-256 fingerprint pinning in `security_profile.h` — STRICT mode rejects unrecognised keys
- **Status:** Mitigated ✅

### R-004 — Unencrypted Key Storage in Flash
- **Category:** Physical Security
- **Inherent Risk:** High
- **Residual Risk:** Medium
- **Control (Partial):** Key stored in dedicated flash region — no AES-XTS wrap yet; physical access required
- **Status:** Accepted ⚠️

### R-005 — Rate Limit Bypass via Flooding
- **Category:** Availability
- **Inherent Risk:** Medium
- **Residual Risk:** Low
- **Control:** Receiver enforces 8 requests/second limit — excess returns TOO_MANY_REQUESTS
- **Status:** Mitigated ✅

### R-006 — Key Exhaustion Beyond Max Message Count
- **Category:** Key Lifecycle
- **Inherent Risk:** Medium
- **Residual Risk:** Low
- **Control:** Receiver tracks `message_count` and sets `rotation_required` flag at 250 messages
- **Status:** Mitigated ✅

### R-007 — CoAP URI Path Injection
- **Category:** Protocol Security
- **Inherent Risk:** Medium
- **Residual Risk:** Low
- **Control:** Only `/pqkem-pk` and `/pqkem-data` accepted — others return BAD_REQUEST
- **Status:** Mitigated ✅

### R-008 — Wi-Fi Network Eavesdropping
- **Category:** Network Security
- **Inherent Risk:** High
- **Residual Risk:** Medium
- **Control:** All payload encrypted with AES-128-CCM — network headers visible but payload confidential
- **Status:** Mitigated ✅

### R-009 — Firmware Tampering via Re-flash
- **Category:** Physical Security
- **Inherent Risk:** High (Critical Impact)
- **Residual Risk:** Medium
- **Control (Partial):** IO8 flashing mode requires physical hardware bridge — no secure boot yet
- **Status:** Accepted ⚠️

### R-010 — TOFU First-Use Key Spoofing
- **Category:** Key Management
- **Inherent Risk:** High
- **Residual Risk:** Medium
- **Control (Partial):** TOFU only in test/demo mode — production should use STRICT with provisioned fingerprint
- **Status:** Accepted ⚠️

---

## Controls Summary

| Control Type | Count |
|---|---|
| Fully implemented | 7 |
| Partially implemented | 3 |
| Not implemented | 0 |

---

## Recommended Next Steps

1. **Secure flash storage** — wrap ML-KEM private key with AES-XTS before writing to BL602 flash (addresses R-004)
2. **Enable secure boot** — verify firmware signature before execution (addresses R-009)
3. **Enforce STRICT mode** for production deployments — provision real SHA-256 fingerprint in `security_profile.h` (addresses R-010)
4. **Nonce persistence** — persist nonce cache across reboots to prevent replay via power-cycle attacks (strengthens R-001)
5. **Certificate-based CoAP (DTLS)** — add transport-layer security for network header protection (strengthens R-008)
