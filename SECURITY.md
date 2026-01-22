# SECURITY.md

# Security Analysis of the Secure Communication Protocol

## Overview
This document outlines the security measures implemented in the secure communication protocol designed for a centralized analytics server communicating with multiple clients in a hostile network environment. The protocol ensures confidentiality, integrity, freshness, and synchronization using symmetric cryptographic techniques.

## Security Goals
1. **Confidentiality**: Ensures that only authorized parties can read the messages exchanged between the server and clients.
2. **Integrity**: Guarantees that the messages have not been altered in transit.
3. **Freshness**: Prevents replay attacks by ensuring that old messages cannot be reused.
4. **Synchronization**: Maintains the correct state between the server and clients, terminating sessions upon desynchronization.

## Threat Model
The protocol is designed to withstand attacks from an active adversary capable of:
- Replay attacks
- Message modification
- Dropping or reordering packets
- Reflecting messages back to the sender

## Security Measures

### 1. HMAC-SHA256 for Integrity (Encrypt-then-MAC)
Each message includes an HMAC-SHA256 tag computed over `(IV || Ciphertext)`. The HMAC is verified **before** decryption (Encrypt-then-MAC pattern), preventing any processing of tampered data. Constant-time comparison (`hmac.compare_digest`) is used to prevent timing attacks.

### 2. Round Number Verification
The protocol maintains a current round number for each client (starting from 1). Each message must include the expected round number, verified before processing. Messages with stale or future round numbers cause immediate session termination, preventing replay attacks.

### 3. Key Evolution (Ratcheting)
Keys are evolved after each successful message exchange using SHA-256:
- **C2S Keys**: `Enc_{R+1} = H(Enc_R || Ciphertext_R)`, `Mac_{R+1} = H(Mac_R || Nonce_R)`
- **S2C Keys**: `Enc_{R+1} = H(Enc_R || AggregatedData_R)`, `Mac_{R+1} = H(Mac_R || StatusCode_R)`

This ratcheting mechanism provides forward secrecy - compromised keys cannot decrypt past messages.

### 4. Session Termination on Failure
Any security violation immediately terminates the session via `TERMINATE` opcode:
- HMAC verification failure
- Round number mismatch
- Invalid opcode for current state
- Decryption/padding errors

### 5. Manual PKCS#7 Padding
The protocol implements manual PKCS#7 padding with validation:
- Padding length must be 1-16 bytes
- All padding bytes must match the padding length
- Invalid padding raises `ValueError`, terminating the session

### 6. Directional Keys
Separate encryption and MAC keys for each direction (Client-to-Server and Server-to-Client) prevent reflection attacks where messages are sent back to the sender.

### 7. Active Adversary Testing
The `attacks.py` component simulates various MITM attacks:
- Ciphertext modification (bit flipping)
- HMAC tampering
- Round number manipulation
- Message dropping and reordering
- Replay attacks
- Reflection attacks

All attacks are detected and result in session termination.

---

## Security Against Attack Scenarios

This section provides a detailed analysis of how the protocol defends against each specific attack scenario that an active adversary might attempt.

### 1. Replay Attack Defense

**Attack Description**: An attacker captures a legitimate message and retransmits it later to trick the server or client into processing it again.

**How the Protocol Defends**:
- **Round Number Verification**: Each message contains a round number that must match the expected round at the receiver. The protocol maintains strict round synchronization:
  ```
  if round_num != self.round_number:
      self.state = ProtocolState.TERMINATED
      return None
  ```
- **Key Evolution**: Even if an attacker replays a message with the correct round number, the keys have already evolved after each successful exchange. The replayed message will fail HMAC verification because it was signed with old keys.
- **Stateful Protocol**: The FSM tracks the current state (INIT → ACTIVE → TERMINATED). Replaying a CLIENT_HELLO during ACTIVE state is rejected.

**Result**: Replayed messages are detected via round mismatch or HMAC failure, causing immediate session termination.

---

### 2. Message Modification Attack Defense

**Attack Description**: An attacker intercepts a message and modifies its content (ciphertext) before forwarding it.

**How the Protocol Defends**:
- **HMAC-SHA256 Authentication**: Every message includes an HMAC computed over `(IV || Ciphertext)`:
  ```python
  hmac_tag = hmac_sha256(mac_key, iv + ciphertext)
  ```
- **Encrypt-then-MAC Pattern**: The HMAC is verified BEFORE decryption:
  ```python
  if not hmac_verify(mac_key, iv + ciphertext, hmac_tag):
      raise ValueError("HMAC verification failed")
  ```
- **Any bit flip in ciphertext invalidates the HMAC**: The probability of randomly generating a valid HMAC is 1/2^256, which is computationally infeasible.

**Result**: Modified messages fail HMAC verification → Session terminated. The attacker cannot forge a valid HMAC without knowing the MAC key.

---

### 3. HMAC Tampering Attack Defense

**Attack Description**: An attacker attempts to modify or forge the HMAC authentication tag.

**How the Protocol Defends**:
- **256-bit HMAC Tags**: HMAC-SHA256 produces 32-byte tags, providing 256-bit security against forgery.
- **Secret MAC Keys**: The MAC keys are derived from the pre-shared master key and evolved after each round. Without the key, forging a valid HMAC is computationally infeasible.
- **Constant-Time Comparison**: The protocol uses `hmac.compare_digest()` to compare HMACs:
  ```python
  return hmac_lib.compare_digest(computed, expected_hmac)
  ```
  This prevents timing attacks that could leak information about the expected HMAC.

**Result**: Tampered HMACs are detected immediately → Session terminated.

---

### 4. Round Number Manipulation Attack Defense

**Attack Description**: An attacker modifies the round number in a message to cause desynchronization or bypass replay protection.

**How the Protocol Defends**:
- **Strict Round Checking**: Both client and server verify that the received round matches their expected round exactly.
- **HMAC Coverage**: While the round number in the header is not directly covered by HMAC, the round synchronization is enforced through the key evolution mechanism. If an attacker changes the round number:
  - If they set a future round: The receiver hasn't evolved keys yet → HMAC will fail
  - If they set a past round: The receiver has already evolved past those keys → HMAC will fail
- **Immediate Termination**: Any round mismatch immediately terminates the session:
  ```python
  print(f"[FSM] Round mismatch: expected {self.round_number}, got {round_num}")
  self.state = ProtocolState.TERMINATED
  ```

**Result**: Round manipulation causes KEY_DESYNC_ERROR → Session terminated.

---

### 5. Message Dropping Attack Defense

**Attack Description**: An attacker selectively drops messages to disrupt communication.

**How the Protocol Defends**:
- **Timeout Mechanisms**: The client and server implement socket timeouts (2 seconds) when waiting for responses:
  ```python
  self.socket.settimeout(2.0)
  remaining = self.socket.recv(4096)
  ```
- **Session Awareness**: If an expected response is not received, the connection is closed gracefully.
- **Round Synchronization**: If a message is dropped and communication somehow continues, the round numbers will be out of sync, triggering termination on the next message.

**Result**: Dropped messages cause communication failure or round desynchronization → Session terminated or connection closed.

---

### 6. Message Reordering Attack Defense

**Attack Description**: An attacker buffers multiple messages and sends them in a different order.

**How the Protocol Defends**:
- **Sequential Round Numbers**: Messages must arrive in strict order (Round 1, then Round 2, etc.). Out-of-order messages have incorrect round numbers.
- **Immediate Rejection**: A message with an unexpected round number (whether higher or lower) is immediately rejected:
  ```python
  if round_num != self.round_number:
      # Round mismatch - reject message
      self.state = ProtocolState.TERMINATED
  ```
- **Key Synchronization**: Even if round numbers matched, the keys evolve sequentially. An out-of-order message would use wrong keys → HMAC verification fails.

**Result**: Reordered messages trigger round mismatch → Session terminated.

---

### 7. Reflection Attack Defense

**Attack Description**: An attacker captures a message and sends it back to the original sender (e.g., reflecting a client message back to the client).

**How the Protocol Defends**:
- **Directional Keys**: The protocol uses separate key pairs for each direction:
  - **C2S Keys**: `C2S_Enc_Key`, `C2S_Mac_Key` for client-to-server messages
  - **S2C Keys**: `S2C_Enc_Key`, `S2C_Mac_Key` for server-to-client messages
  ```python
  c2s_enc = derive_key(master_key, "C2S-ENC")
  c2s_mac = derive_key(master_key, "C2S-MAC")
  s2c_enc = derive_key(master_key, "S2C-ENC")
  s2c_mac = derive_key(master_key, "S2C-MAC")
  ```
- **Direction Byte Verification**: Each message includes a direction byte (0 = C2S, 1 = S2C). The receiver uses this to select the appropriate keys.
- **Key Mismatch on Reflection**: If an attacker reflects a C2S message back to the client (flipping direction to S2C), the client will try to verify using S2C_Mac_Key, but the message was signed with C2S_Mac_Key → HMAC verification fails.

**Result**: Reflected messages fail HMAC verification due to key mismatch → Session terminated.

---

### 8. Key Compromise and Forward Secrecy

**Attack Description**: An attacker compromises the current session keys and attempts to decrypt past or future messages.

**How the Protocol Defends**:
- **Key Ratcheting**: Keys evolve after each message exchange using one-way hash functions:
  ```python
  new_enc = evolve_key(self.c2s_enc_key, ciphertext)  # H(key || ciphertext)
  new_mac = evolve_key(self.c2s_mac_key, nonce)       # H(key || nonce)
  ```
- **Forward Secrecy**: Since keys are derived using SHA-256 (a one-way function), compromising the current key does NOT allow:
  - **Backward recovery**: Cannot compute previous keys from current key
  - **Past message decryption**: Old messages were encrypted with keys that cannot be recovered
- **Message-Dependent Evolution**: Keys are mixed with message-specific data (ciphertext, nonce), ensuring unique key sequences even for identical payloads.

**Result**: Compromised keys cannot decrypt past messages; future messages use evolved keys unknown to the attacker.

---

### 9. Padding Oracle Attack Defense

**Attack Description**: An attacker exploits error messages from invalid padding to decrypt ciphertext byte-by-byte.

**How the Protocol Defends**:
- **Encrypt-then-MAC**: HMAC is verified BEFORE any decryption or padding validation occurs:
  ```python
  # Verify HMAC BEFORE decryption
  if not hmac_verify(mac_key, iv + ciphertext, hmac_tag):
      raise ValueError("HMAC verification failed")
  # Only then decrypt
  plaintext = aes_cbc_decrypt(ciphertext, enc_key, iv)
  ```
- **No Padding Error Leakage**: An attacker cannot craft messages to probe padding validity because:
  1. Invalid HMAC → Rejected before decryption
  2. Valid HMAC requires knowing the MAC key (which attacker doesn't have)
- **Uniform Error Response**: All failures result in the same action: session termination with a generic error.

**Result**: The padding oracle attack vector is eliminated by the Encrypt-then-MAC construction.

---

### 10. Man-in-the-Middle (MITM) Attack Summary

**Attack Description**: An attacker positions themselves between client and server, intercepting all communication.

**How the Protocol Defends Against MITM**:

| MITM Capability | Protocol Defense | Result |
|-----------------|------------------|--------|
| Read messages | AES-128-CBC encryption | Messages are encrypted; attacker sees only ciphertext |
| Modify messages | HMAC-SHA256 | Modifications detected via HMAC failure |
| Replay messages | Round numbers + Key evolution | Replays rejected due to round mismatch or wrong keys |
| Inject messages | Pre-shared master keys | Attacker cannot generate valid HMAC without keys |
| Drop messages | Timeouts + Round sync | Session terminated on missing responses |
| Reorder messages | Sequential round enforcement | Out-of-order messages rejected |
| Reflect messages | Directional keys | Reflected messages fail HMAC verification |

**Result**: A MITM attacker without knowledge of the pre-shared master keys cannot successfully attack the protocol. All active attacks are detected and cause session termination.

---

## Implementation Details

### Cryptographic Primitives
- **Encryption**: AES-128-CBC (PyCryptodome)
- **Integrity**: HMAC-SHA256 (32-byte tag)
- **Key Derivation**: SHA-256 with labels ("C2S-ENC", "C2S-MAC", "S2C-ENC", "S2C-MAC")
- **Random Generation**: `Crypto.Random.get_random_bytes` for IVs and nonces

### Message Format
| Field | Size | Description |
|-------|------|-------------|
| Opcode | 1 byte | Message type (10-60) |
| Client ID | 1 byte | Client identifier (1-5) |
| Round | 4 bytes | Round number (big-endian) |
| Direction | 1 byte | 0=C2S, 1=S2C |
| IV | 16 bytes | AES initialization vector |
| Ciphertext | Variable | Encrypted payload |
| HMAC | 32 bytes | HMAC-SHA256 tag |

### Protocol State Machine
Three states: `INIT` → `ACTIVE` → `TERMINATED`
- `INIT`: Only CLIENT_HELLO and SERVER_CHALLENGE allowed
- `ACTIVE`: Data exchange (CLIENT_DATA, SERVER_AGGR_RESPONSE)
- `TERMINATED`: Session ended, no further communication

## Conclusion
The designed protocol incorporates multiple layers of security to protect against a variety of attacks in a hostile network environment. By leveraging HMAC-SHA256 for integrity, maintaining stateful communication with round numbers, implementing key ratcheting for forward secrecy, and enforcing strict session management, the protocol ensures secure multi-client communication.