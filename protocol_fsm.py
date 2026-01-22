import struct
from enum import IntEnum
from crypto_utils import derive_key, evolve_key, encrypt, decrypt, generate_nonce

class ProtocolState(IntEnum):
    """Protocol states"""
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2

class Opcode(IntEnum):
    """Protocol opcodes"""
    CLIENT_HELLO = 10
    SERVER_CHALLENGE = 20
    CLIENT_DATA = 30
    SERVER_AGGR_RESPONSE = 40
    KEY_DESYNC_ERROR = 50
    TERMINATE = 60

class Direction(IntEnum):
    """Message direction"""
    CLIENT_TO_SERVER = 0
    SERVER_TO_CLIENT = 1

class ProtocolFSM:
    def __init__(self, client_id, master_key):
        self.client_id = client_id
        self.master_key = master_key
        self.round_number = 1  # Start rounds from 1 instead of 0
        self.state = ProtocolState.INIT
        
        # Initialize keys from master key
        # C2S_Enc_0 = H(K_i || "C2S-ENC")
        # C2S_Mac_0 = H(K_i || "C2S-MAC")
        # S2C_Enc_0 = H(K_i || "S2C-ENC")
        # S2C_Mac_0 = H(K_i || "S2C-MAC")
        c2s_enc = derive_key(master_key, "C2S-ENC")
        c2s_mac = derive_key(master_key, "C2S-MAC")
        s2c_enc = derive_key(master_key, "S2C-ENC")
        s2c_mac = derive_key(master_key, "S2C-MAC")
        
        # Truncate to 16 bytes for AES-128
        self.c2s_enc_key = c2s_enc[:16]
        self.c2s_mac_key = c2s_mac
        self.s2c_enc_key = s2c_enc[:16]
        self.s2c_mac_key = s2c_mac
        
        # For key evolution
        self.last_c2s_ciphertext = b''
        self.last_c2s_nonce = b''
        self.last_s2c_aggregated = b''
        self.last_s2c_status = b''

    def send_message(self, opcode, payload):
        """
        Construct and encrypt a message to send.
        Returns complete message bytes ready to send.
        """
        # Determine direction and keys
        if opcode in [Opcode.SERVER_CHALLENGE, Opcode.SERVER_AGGR_RESPONSE, Opcode.TERMINATE]:
            direction = Direction.SERVER_TO_CLIENT
            enc_key = self.s2c_enc_key
            mac_key = self.s2c_mac_key
        else:
            direction = Direction.CLIENT_TO_SERVER
            enc_key = self.c2s_enc_key
            mac_key = self.c2s_mac_key
        
        # Encrypt payload
        iv, ciphertext, hmac_tag = encrypt(payload, enc_key, mac_key)
        
        # Build message header with CURRENT round number
        header = struct.pack('!B B I B', opcode, self.client_id, self.round_number, direction)
        
        # Complete message: Header || IV || Ciphertext || HMAC
        message = header + iv + ciphertext + hmac_tag
        
        # Store for key evolution
        if direction == Direction.SERVER_TO_CLIENT:
            self.last_s2c_aggregated = ciphertext
            self.last_s2c_status = bytes([opcode])
        
        # Evolve keys AFTER sending
        self.evolve_keys(direction, ciphertext, iv, opcode)
        
        # Increment round AFTER sending response from server
        # Only server increments after sending SERVER_AGGR_RESPONSE
        if opcode == Opcode.SERVER_AGGR_RESPONSE:
            self.round_number += 1
        
        return message
    
    def receive_message(self, expected_opcode, round_num, direction, iv, ciphertext, hmac_tag):
        """
        Verify and decrypt a received message.
        Returns plaintext if valid, None if invalid (terminates session).
        """
        # Verify round number
        if round_num != self.round_number:
            print(f"[FSM] Round mismatch: expected {self.round_number}, got {round_num}")
            self.state = ProtocolState.TERMINATED
            return None
        
        # Verify state and opcode
        if not self.validate_opcode(expected_opcode):
            print(f"[FSM] Invalid opcode {expected_opcode} for state {self.state}")
            self.state = ProtocolState.TERMINATED
            return None
        
        # Determine keys based on direction
        if direction == Direction.CLIENT_TO_SERVER:
            enc_key = self.c2s_enc_key
            mac_key = self.c2s_mac_key
        else:
            enc_key = self.s2c_enc_key
            mac_key = self.s2c_mac_key
        
        # Decrypt and verify
        try:
            plaintext = decrypt(iv, ciphertext, hmac_tag, enc_key, mac_key)
        except ValueError as e:
            print(f"[FSM] Decryption/HMAC failed: {e}")
            self.state = ProtocolState.TERMINATED
            return None
        
        # Store for key evolution
        if direction == Direction.CLIENT_TO_SERVER:
            self.last_c2s_ciphertext = ciphertext
            self.last_c2s_nonce = iv
        
        # Update state
        self.update_state(expected_opcode)
        
        # Evolve keys after successful processing
        self.evolve_keys(direction, ciphertext, iv, expected_opcode)
        
        # Increment round AFTER receiving SERVER_AGGR_RESPONSE from server
        # Only client increments after receiving the response
        if expected_opcode == Opcode.SERVER_AGGR_RESPONSE:
            self.round_number += 1
        
        return plaintext
    
    def validate_opcode(self, opcode):
        """Validate opcode is allowed in current state"""
        if self.state == ProtocolState.INIT:
            # In INIT state, client can send CLIENT_HELLO, server can respond with SERVER_CHALLENGE
            return opcode in [Opcode.CLIENT_HELLO, Opcode.SERVER_CHALLENGE]
        elif self.state == ProtocolState.ACTIVE:
            return opcode in [Opcode.SERVER_CHALLENGE, Opcode.CLIENT_DATA, 
                            Opcode.SERVER_AGGR_RESPONSE, Opcode.TERMINATE]
        else:
            return False
    
    def update_state(self, opcode):
        """Update FSM state based on opcode"""
        if opcode == Opcode.CLIENT_HELLO or opcode == Opcode.SERVER_CHALLENGE:
            # Transition to ACTIVE after handshake messages
            self.state = ProtocolState.ACTIVE
        elif opcode == Opcode.TERMINATE:
            self.state = ProtocolState.TERMINATED
    
    def evolve_keys(self, direction, ciphertext, nonce, opcode):
        """
        Evolve keys according to protocol specification.
        C2S_Enc_R+1 = H(C2S_Enc_R || Ciphertext_R)
        C2S_Mac_R+1 = H(C2S_Mac_R || Nonce_R)
        S2C_Enc_R+1 = H(S2C_Enc_R || AggregatedData_R)
        S2C_Mac_R+1 = H(S2C_Mac_R || StatusCode_R)
        """
        if direction == Direction.CLIENT_TO_SERVER:
            # Evolve client-to-server keys
            new_enc = evolve_key(self.c2s_enc_key, ciphertext)
            new_mac = evolve_key(self.c2s_mac_key, nonce)
            self.c2s_enc_key = new_enc[:16]
            self.c2s_mac_key = new_mac
        else:
            # Evolve server-to-client keys
            new_enc = evolve_key(self.s2c_enc_key, ciphertext)
            new_mac = evolve_key(self.s2c_mac_key, bytes([opcode]))
            self.s2c_enc_key = new_enc[:16]
            self.s2c_mac_key = new_mac