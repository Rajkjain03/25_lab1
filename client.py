import socket
import os
import sys
import argparse
import struct
import signal
from crypto_utils import encrypt, decrypt, hmac_verify, generate_nonce
from protocol_fsm import ProtocolFSM, ProtocolState, Opcode, Direction

class Client:
    def __init__(self, client_id, server_host, server_port, master_key):
        self.client_id = client_id
        self.server_host = server_host
        self.server_port = server_port
        self.master_key = master_key
        self.fsm = ProtocolFSM(client_id, master_key)
        self.socket = None
        self.running = True
        
        # Setup signal handler for Ctrl+C
        signal.signal(signal.SIGINT, self.signal_handler)
        
        print(f"[CLIENT {client_id}] Initialized")

    def signal_handler(self, sig, frame):
        """Handle Ctrl+C gracefully"""
        print(f"\n[CLIENT {self.client_id}] Shutting down...")
        self.running = False
        if self.socket:
            self.socket.close()
        sys.exit(0)

    def connect(self):
        """Connect to server (or attacker)"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            print(f"[CLIENT {self.client_id}] Connected to {self.server_host}:{self.server_port}")
            return True
        except Exception as e:
            print(f"[CLIENT {self.client_id}] Connection failed: {e}")
            return False

    def send_client_hello(self):
        """Send CLIENT_HELLO to initiate protocol"""
        try:
            hello_data = f"HELLO from client {self.client_id}".encode('utf-8')
            message = self.fsm.send_message(Opcode.CLIENT_HELLO, hello_data)
            self.socket.sendall(message)
            print(f"[CLIENT {self.client_id}] Sent CLIENT_HELLO")
            
            # Wait for SERVER_CHALLENGE
            response = self.receive_message()
            if response:
                self.handle_server_challenge(response)
                return True
        except Exception as e:
            print(f"[CLIENT {self.client_id}] Error in handshake: {e}")
            return False

    def send_client_data(self, data_value):
        """Send CLIENT_DATA with numeric value"""
        try:
            data_str = f"DATA:{data_value}"
            current_round = self.fsm.round_number
            message = self.fsm.send_message(Opcode.CLIENT_DATA, data_str.encode('utf-8'))
            self.socket.sendall(message)
            print(f"[CLIENT {self.client_id}] Sent CLIENT_DATA")
            print(f"  Round:  {current_round}")
            print(f"  Data:   {data_value}")
            
            # Wait for SERVER_AGGR_RESPONSE
            response = self.receive_message()
            if response:
                self.handle_server_response(response)
                return True
        except Exception as e:
            print(f"[CLIENT {self.client_id}] Error sending data: {e}")
            return False

    def receive_message(self):
        """Receive a complete message from server"""
        try:
            # Receive header first
            header = self.recv_exact(23)
            if not header:
                return None
            
            # Receive rest of message (don't block waiting for exact size)
            self.socket.settimeout(2.0)
            remaining = self.socket.recv(4096)
            self.socket.settimeout(None)
            
            if not remaining:
                return None
            
            return header + remaining
        except socket.timeout:
            print(f"[CLIENT {self.client_id}] Receive timeout")
            return None
        except Exception as e:
            print(f"[CLIENT {self.client_id}] Error receiving: {e}")
            return None

    def recv_exact(self, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = self.socket.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def parse_message(self, message):
        """Parse received message"""
        try:
            if len(message) < 55:
                return None
            
            opcode = message[0]
            client_id = message[1]
            round_num = struct.unpack('!I', message[2:6])[0]
            direction = message[6]
            iv = message[7:23]
            hmac_tag = message[-32:]
            ciphertext = message[23:-32]
            
            return (opcode, client_id, round_num, direction, iv, ciphertext, hmac_tag)
        except:
            return None

    def handle_server_challenge(self, message):
        """Handle SERVER_CHALLENGE response"""
        parsed = self.parse_message(message)
        if not parsed:
            print(f"[CLIENT {self.client_id}] Invalid message format")
            return False
        
        opcode, _, round_num, direction, iv, ciphertext, hmac_tag = parsed
        
        if opcode == Opcode.TERMINATE:
            print(f"[CLIENT {self.client_id}] Server terminated session")
            self.running = False
            return False
        
        # Decrypt challenge
        plaintext = self.fsm.receive_message(Opcode.SERVER_CHALLENGE, round_num, direction, iv, ciphertext, hmac_tag)
        
        if plaintext is None:
            print(f"[CLIENT {self.client_id}] Failed to process SERVER_CHALLENGE")
            self.running = False
            return False
        
        challenge_text = plaintext.decode('utf-8', errors='ignore')
        print(f"[CLIENT {self.client_id}] Received SERVER_CHALLENGE")
        print(f"  Round:     {round_num}")
        print(f"  Challenge: {challenge_text}")
        return True

    def handle_server_response(self, message):
        """Handle SERVER_AGGR_RESPONSE"""
        parsed = self.parse_message(message)
        if not parsed:
            print(f"[CLIENT {self.client_id}] Invalid message format")
            return False
        
        opcode, _, round_num, direction, iv, ciphertext, hmac_tag = parsed
        
        if opcode == Opcode.TERMINATE:
            print(f"[CLIENT {self.client_id}] SERVER TERMINATED SESSION")
            print(f"  Reason: Attack detected or protocol violation")
            self.running = False
            return False
        
        # Decrypt response
        plaintext = self.fsm.receive_message(Opcode.SERVER_AGGR_RESPONSE, round_num, direction, iv, ciphertext, hmac_tag)
        
        if plaintext is None:
            print(f"[CLIENT {self.client_id}] Failed to process server response")
            self.running = False
            return False
        
        response_text = plaintext.decode('utf-8', errors='ignore')
        print(f"[CLIENT {self.client_id}] Received SERVER_AGGR_RESPONSE")
        print(f"  Round:    {round_num}")
        print(f"  Response: {response_text}")
        return True

    def run(self):
        """Main client loop"""
        if not self.connect():
            return
        
        # Perform handshake
        if not self.send_client_hello():
            print(f"[CLIENT {self.client_id}] Handshake failed")
            return
        
        print(f"\n[CLIENT {self.client_id}] Ready! Type numeric values to send.")
        print(f"[CLIENT {self.client_id}] Press Ctrl+C to exit.\n")
        
        # Main data exchange loop
        try:
            while self.running:
                user_input = input(f"[CLIENT {self.client_id}] > ")
                
                if not user_input.strip():
                    continue
                
                try:
                    # Parse as float to validate numeric input
                    value = float(user_input.strip())
                    
                    if not self.send_client_data(value):
                        print(f"[CLIENT {self.client_id}] Failed to send data")
                        break
                        
                except ValueError:
                    print(f"[CLIENT {self.client_id}] Please enter a numeric value")
                except Exception as e:
                    print(f"[CLIENT {self.client_id}] Error: {e}")
                    break
                    
        except KeyboardInterrupt:
            print(f"\n[CLIENT {self.client_id}] Interrupted by user")
        finally:
            if self.socket:
                self.socket.close()
            print(f"[CLIENT {self.client_id}] Disconnected")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Secure Communication Client')
    parser.add_argument('--host', default='127.0.0.1', help='Server host (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5001, help='Server port (default: 5001 for attacker)')
    parser.add_argument('--client-id', type=int, default=1, help='Client ID (1-5)')
    
    args = parser.parse_args()
    
    # Pre-shared master keys (must match server's keys)
    MASTER_KEYS = {
        1: b'client1_master_k',
        2: b'client2_master_k',
        3: b'client3_master_k',
        4: b'client4_master_k',
        5: b'client5_master_k',
    }
    
    if args.client_id not in MASTER_KEYS:
        print(f"Invalid client ID. Must be 1-5")
        sys.exit(1)
    
    master_key = MASTER_KEYS[args.client_id]
    
    client = Client(args.client_id, args.host, args.port, master_key)
    client.run()