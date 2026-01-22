import socket
import threading
import json
import os
import struct
from crypto_utils import encrypt, decrypt, hmac_verify, generate_nonce, derive_key, evolve_key
from protocol_fsm import ProtocolFSM, ProtocolState, Opcode

# Configuration constants
SERVER_PORT = 5000
MAX_CLIENTS = 5

class SecureServer:
    def __init__(self):
        self.clients = {}
        # Don't create a single FSM - create one per client
        self.client_fsms = {}  # client_id -> ProtocolFSM
        self.aggregated_data = {}
        self.round_data = {}  # round_number -> list of values
        self.round_lock = threading.Lock()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', SERVER_PORT))
        self.server_socket.listen(MAX_CLIENTS)
        
        # Pre-shared master keys for clients
        self.master_keys = {
            1: b'client1_master_k',  # 16 bytes for AES-128
            2: b'client2_master_k',
            3: b'client3_master_k',
            4: b'client4_master_k',
            5: b'client5_master_k',
        }
        
        print(f"[SERVER] Server listening on port {SERVER_PORT}")

    def handle_client(self, client_socket, client_address):
        print(f"[SERVER] Connection from {client_address} established.")
        client_id = None
        fsm = None
        
        try:
            while True:
                message = self.receive_message(client_socket)
                if not message:
                    print(f"[SERVER] Client {client_address} disconnected")
                    break
                
                # Parse message
                parsed = self.parse_message(message)
                if not parsed:
                    print(f"[SERVER] Invalid message format")
                    break
                
                opcode, recv_client_id, round_num, direction, iv, ciphertext, hmac_tag = parsed
                
                # Initialize FSM on first message (CLIENT_HELLO)
                if fsm is None:
                    if opcode != Opcode.CLIENT_HELLO:
                        print(f"[SERVER] Expected CLIENT_HELLO, got {opcode}")
                        break
                    
                    client_id = recv_client_id
                    
                    if client_id not in self.master_keys:
                        print(f"[SERVER] Unknown client ID: {client_id}")
                        break
                    
                    # Create FSM for this client
                    master_key = self.master_keys[client_id]
                    fsm = ProtocolFSM(client_id, master_key)
                    self.client_fsms[client_id] = fsm
                    self.clients[client_id] = {'socket': client_socket, 'fsm': fsm}
                    
                    print(f"[SERVER] Client {client_id} initialized")
                
                # Process message
                response = self.process_message(fsm, opcode, round_num, direction, iv, ciphertext, hmac_tag)
                
                if response:
                    client_socket.sendall(response)
                
                # Check termination
                if fsm.state == ProtocolState.TERMINATED:
                    print(f"[SERVER] Session with client {client_id} terminated")
                    break
                    
        except Exception as e:
            print(f"[SERVER] Error with client {client_address}: {e}")
            import traceback
            traceback.print_exc()
        finally:
            if client_id:
                self.client_fsms.pop(client_id, None)
                self.clients.pop(client_id, None)
            client_socket.close()
            print(f"[SERVER] Connection from {client_address} closed.")

    def process_message(self, fsm, opcode, round_num, direction, iv, ciphertext, hmac_tag):
        """Process message through FSM"""
        try:
            if opcode == Opcode.CLIENT_HELLO:
                return self.handle_client_hello(fsm, round_num, direction, iv, ciphertext, hmac_tag)
            
            elif opcode == Opcode.CLIENT_DATA:
                return self.handle_client_data(fsm, round_num, direction, iv, ciphertext, hmac_tag)
            
            else:
                print(f"[SERVER] Unexpected opcode {opcode}")
                return self.send_terminate(fsm)
        except Exception as e:
            print(f"[SERVER] Error processing message: {e}")
            return self.send_terminate(fsm)
    
    def handle_client_hello(self, fsm, round_num, direction, iv, ciphertext, hmac_tag):
        """Handle CLIENT_HELLO"""
        plaintext = fsm.receive_message(Opcode.CLIENT_HELLO, round_num, direction, iv, ciphertext, hmac_tag)
        
        if plaintext is None:
            return self.send_terminate(fsm)
        
        print(f"[SERVER] CLIENT_HELLO from client {fsm.client_id}: {plaintext.decode('utf-8', errors='ignore')}")
        
        # Send challenge
        challenge = generate_nonce(16)
        response_data = b"CHALLENGE:" + challenge
        
        return fsm.send_message(Opcode.SERVER_CHALLENGE, response_data)
    
    def handle_client_data(self, fsm, round_num, direction, iv, ciphertext, hmac_tag):
        """Handle CLIENT_DATA"""
        plaintext = fsm.receive_message(Opcode.CLIENT_DATA, round_num, direction, iv, ciphertext, hmac_tag)
        
        if plaintext is None:
            return self.send_terminate(fsm)
        
        print(f"[SERVER] CLIENT_DATA from client {fsm.client_id} (Round {round_num}): {plaintext.decode('utf-8', errors='ignore')}")
        
        # Extract numeric value
        try:
            data_str = plaintext.decode('utf-8')
            if data_str.startswith("DATA:"):
                value = float(data_str.split(":")[1])
                
                # Aggregate
                with self.round_lock:
                    if round_num not in self.round_data:
                        self.round_data[round_num] = []
                    self.round_data[round_num].append(value)
                
                aggregate = sum(self.round_data[round_num])
                count = len(self.round_data[round_num])
                
                response_data = f"AGGREGATE:sum={aggregate:.2f},count={count}".encode('utf-8')
                
                return fsm.send_message(Opcode.SERVER_AGGR_RESPONSE, response_data)
        except Exception as e:
            print(f"[SERVER] Error parsing data: {e}")
            return self.send_terminate(fsm)
    
    def send_terminate(self, fsm):
        """Send TERMINATE"""
        fsm.state = ProtocolState.TERMINATED
        return fsm.send_message(Opcode.TERMINATE, b"Session terminated")
    
    def receive_message(self, sock):
        """Receive complete message"""
        try:
            # Receive header first to determine message size
            header = self.recv_exact(sock, 23)
            if not header:
                return None
            
            # Get ciphertext length from what's available
            # We need to read until we have: ciphertext (variable) + HMAC (32)
            # For simplicity, receive up to 4KB more
            sock.settimeout(2.0)  # Set timeout to avoid blocking forever
            remaining = sock.recv(4096)
            sock.settimeout(None)  # Reset timeout
            
            if not remaining:
                return None
            
            return header + remaining
        except socket.timeout:
            print("[SERVER] Receive timeout")
            return None
        except:
            return None
    
    def recv_exact(self, sock, n):
        """Receive exactly n bytes"""
        data = b''
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def parse_message(self, message):
        """Parse message format"""
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

    def start(self):
        print(f"[SERVER] Ready to accept connections...")
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address), daemon=True)
                client_thread.start()
        except KeyboardInterrupt:
            print("\n[SERVER] Shutting down...")
        finally:
            self.server_socket.close()

if __name__ == "__main__":
    server = SecureServer()
    server.start()