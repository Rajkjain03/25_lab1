# Author
Raj k jain - 2025201036
Shubham sunny - 2025201025
Qasim naik - 2025201064

## Overview

This project implements a secure communication protocol between a centralized analytics server and multiple clients operating in a hostile network environment. The protocol ensures:

- **Confidentiality**: All messages are encrypted using AES-128-CBC
- **Integrity**: HMAC-SHA256 protects against message tampering
- **Freshness**: Round numbers prevent replay attacks
- **Synchronization**: Key ratcheting ensures forward secrecy

## Project Structure

```
25_lab1/
├── client.py          # Client implementation
├── server.py          # Server implementation  
├── attacks.py         # MITM attacker for testing
├── crypto_utils.py    # Cryptographic primitives
├── protocol_fsm.py    # Protocol state machine
├── README.md          # This file
└── SECURITY.md        # Security analysis
```

## Requirements

- Python 3.8+
- pycryptodome

Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

### 1. Start the Server
```bash
python server.py
```
The server listens on port 5000 by default.

### 2. Start a Client
```bash
python client.py --client-id 1 --port 5000
```
Connect directly to server on port 5000, or use port 5001 to connect through the attacker.

### 3. (Optional) Test with MITM Attacker
```bash
# Terminal 1: Start server
python server.py

# Terminal 2: Start attacker (intercepts traffic on port 5001)
python attacks.py

# Terminal 3: Connect client to attacker
python client.py --client-id 1 --port 5001
```

## Protocol Specification

### Message Format

| Field | Size | Description |
|-------|------|-------------|
| Opcode | 1 byte | Message type |
| Client ID | 1 byte | Client identifier |
| Round | 4 bytes | Round number (big-endian) |
| Direction | 1 byte | 0=C2S, 1=S2C |
| IV | 16 bytes | AES initialization vector |
| Ciphertext | Variable | Encrypted payload |
| HMAC | 32 bytes | HMAC-SHA256 tag |

### Opcodes

| Code | Name | Description |
|------|------|-------------|
| 10 | CLIENT_HELLO | Client initiates session |
| 20 | SERVER_CHALLENGE | Server's challenge response |
| 30 | CLIENT_DATA | Client sends encrypted data |
| 40 | SERVER_AGGR_RESPONSE | Server's aggregated response |
| 50 | KEY_DESYNC_ERROR | Key synchronization error |
| 60 | TERMINATE | Session termination |

### Key Management

**Initial Key Derivation:**
```
C2S_Enc_0 = H(K_master || "C2S-ENC")
C2S_Mac_0 = H(K_master || "C2S-MAC")
S2C_Enc_0 = H(K_master || "S2C-ENC")
S2C_Mac_0 = H(K_master || "S2C-MAC")
```

**Key Evolution (Ratcheting):**
```
C2S_Enc_{R+1} = H(C2S_Enc_R || Ciphertext_R)
C2S_Mac_{R+1} = H(C2S_Mac_R || Nonce_R)
S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)
```

## Security Features

### 1. Replay Attack Prevention
- Each message includes a round number
- Server/client verify expected round number
- Out-of-order messages cause session termination

### 2. Message Integrity
- HMAC-SHA256 computed over (IV || Ciphertext)
- HMAC verified BEFORE decryption (Encrypt-then-MAC)
- Constant-time comparison prevents timing attacks

### 3. Forward Secrecy
- Keys evolve after each successful message exchange
- Compromised keys cannot decrypt past messages

### 4. Session Termination
- Any integrity failure immediately terminates session
- Prevents exploitation of compromised state

## Testing

To test the protocol, run the server and client in separate terminals, then use the MITM attacker to simulate various attacks:

```bash
# Terminal 1: Start server
python server.py

# Terminal 2: Start MITM attacker with interactive menu
python attacks.py

# Terminal 3: Connect client through attacker
python client.py --client-id 1 --port 5001
```

The interactive attacker menu allows you to select different attack modes and observe how the protocol detects and responds to each attack.

## Attack Simulation

The MITM attacker (`attacks.py`) provides an interactive menu with the following attack modes:

| Mode | Description | Expected Result |
|------|-------------|----------------|
| Passive | Forward all messages without modification | Normal operation |
| Modify Ciphertext | Flip bits in encrypted payload | HMAC verification fails → Session terminated |
| Tamper HMAC | Corrupt integrity tag (all 32 bytes) | Integrity check fails → Session terminated |
| Wrong Round | Change round number (+5) | Round mismatch → KEY_DESYNC_ERROR → Terminated |
| Drop Messages | Randomly drop 50% of packets | Communication disrupted |
| Reorder | Buffer and shuffle messages (3 at a time) | Out-of-order round → Session terminated |
| Replay Attack | Resend captured old packets | Duplicate round detected → Session terminated |
| Reflect Attack | Send message back to sender (flip direction) | Wrong keys used → HMAC fails → Terminated |

All attacks are detected by the protocol, causing immediate session termination.

## Client Command Line Options

```bash
python client.py [--host HOST] [--port PORT] [--client-id ID]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | 127.0.0.1 | Server/attacker host address |
| `--port` | 5001 | Port to connect (5000 for direct, 5001 for attacker) |
| `--client-id` | 1 | Client ID (1-5) |

## Client IDs and Keys

The system supports 5 pre-configured clients with shared master keys:

| Client ID | Master Key |
|-----------|------------|
| 1 | client1_master_k |
| 2 | client2_master_k |
| 3 | client3_master_k |
| 4 | client4_master_k |
| 5 | client5_master_k |

## Author

CS5470 - Security of Network Systems - Lab 1

## License

Educational use only.
