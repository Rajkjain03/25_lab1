import socket
import threading
import time
import struct
import random

class MITMAttacker:
    """
    Man-in-the-Middle (MITM) Active Attacker
    
    Capabilities:
    - Intercepts all communication between client and server
    - Can modify, drop, reorder, or replay messages
    """
    
    def __init__(self, listen_host='127.0.0.1', listen_port=5001, server_host='127.0.0.1', server_port=5000):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.server_host = server_host
        self.server_port = server_port
        
        self.attack_mode = "passive"
        self.captured_messages = []
        self.message_buffer = []
        self.old_packets = []
        self.max_old_packets = 5
        self.current_round = 0
        self.active_server_socket = None
        
        self.opcode_names = {
            10: "CLIENT_HELLO",
            20: "SERVER_CHALLENGE", 
            30: "CLIENT_DATA",
            40: "SERVER_AGGR_RESPONSE",
            50: "KEY_DESYNC_ERROR",
            60: "TERMINATE"
        }
        
        print("\n" + "="*60)
        print("MITM ATTACKER INITIALIZED")
        print("="*60)
        print(f"  Listening on:  {listen_host}:{listen_port} (for clients)")
        print(f"  Forwarding to: {server_host}:{server_port} (real server)")
        print(f"  Attack Mode:   {self.attack_mode.upper()}")
        print("="*60 + "\n")
    
    def start(self):
        """Start the MITM proxy"""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.listen_host, self.listen_port))
        listener.listen(5)
        
        print(f"[ATTACKER] Waiting for client connections on port {self.listen_port}...")
        
        try:
            while True:
                client_socket, client_address = listener.accept()
                print("\n" + "-"*60)
                print(f"[ATTACKER] CLIENT CONNECTED: {client_address}")
                print("-"*60)
                
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    server_socket.connect((self.server_host, self.server_port))
                    print(f"[ATTACKER] Connected to server at {self.server_host}:{self.server_port}")
                    
                    client_thread = threading.Thread(
                        target=self.forward_client_to_server,
                        args=(client_socket, server_socket),
                        daemon=True
                    )
                    server_thread = threading.Thread(
                        target=self.forward_server_to_client,
                        args=(server_socket, client_socket),
                        daemon=True
                    )
                    
                    client_thread.start()
                    server_thread.start()
                    
                except Exception as e:
                    print(f"[ATTACKER] Error connecting to server: {e}")
                    client_socket.close()
                    server_socket.close()
                    
        except KeyboardInterrupt:
            print("\n[ATTACKER] Shutting down...")
            listener.close()
    
    def parse_message(self, data):
        """Parse message and return details"""
        if len(data) < 7:
            return None
        
        opcode = data[0]
        client_id = data[1]
        round_num = struct.unpack('!I', data[2:6])[0]
        direction = data[6]
        
        return {
            'opcode': opcode,
            'opcode_name': self.opcode_names.get(opcode, f"UNKNOWN({opcode})"),
            'client_id': client_id,
            'round': round_num,
            'direction': 'Client->Server' if direction == 0 else 'Server->Client',
            'size': len(data)
        }
    
    def display_message(self, data, direction_label, is_modified=False):
        """Display message with clear formatting"""
        msg = self.parse_message(data)
        if not msg:
            return
        
        self.current_round = msg['round']
        
        status = " [MODIFIED]" if is_modified else ""
        print(f"\n[ATTACKER] {direction_label}{status}")
        print(f"  Opcode:    {msg['opcode_name']}")
        print(f"  Client:    {msg['client_id']}")
        print(f"  Round:     {msg['round']}")
        print(f"  Direction: {msg['direction']}")
        print(f"  Size:      {msg['size']} bytes")
    
    def forward_client_to_server(self, client_socket, server_socket):
        """Forward messages from client to server"""
        try:
            self.active_server_socket = server_socket
            
            while True:
                data = client_socket.recv(4096)
                if not data:
                    print("[ATTACKER] Client disconnected")
                    break
                
                self.display_message(data, "CLIENT -> ATTACKER -> SERVER")
                
                self.captured_messages.append(data)
                if len(self.old_packets) < self.max_old_packets:
                    self.old_packets.append(data)
                    print(f"  [Stored packet {len(self.old_packets)}/{self.max_old_packets} for replay]")
                
                modified_data, attack_performed = self.apply_attack(data)
                
                if modified_data:
                    if attack_performed:
                        self.display_message(modified_data, "FORWARDING MODIFIED MESSAGE", is_modified=True)
                    server_socket.sendall(modified_data)
                    print("[ATTACKER] Forwarded to server")
                else:
                    print("[ATTACKER] MESSAGE DROPPED - Server won't receive this")
                    
        except Exception as e:
            print(f"[ATTACKER] Error: {e}")
        finally:
            self.active_server_socket = None
            client_socket.close()
            server_socket.close()
    
    def forward_server_to_client(self, server_socket, client_socket):
        """Forward messages from server to client"""
        try:
            while True:
                data = server_socket.recv(4096)
                if not data:
                    print("[ATTACKER] Server disconnected")
                    break
                
                self.display_message(data, "SERVER -> ATTACKER -> CLIENT")
                self.captured_messages.append(data)
                
                modified_data, attack_performed = self.apply_attack(data)
                
                if modified_data:
                    if attack_performed:
                        self.display_message(modified_data, "FORWARDING MODIFIED MESSAGE", is_modified=True)
                    client_socket.sendall(modified_data)
                    print("[ATTACKER] Forwarded to client")
                else:
                    print("[ATTACKER] MESSAGE DROPPED - Client won't receive this")
                    
        except Exception as e:
            print(f"[ATTACKER] Error: {e}")
        finally:
            server_socket.close()
            client_socket.close()
    
    def apply_attack(self, data):
        """Apply attack based on current mode. Returns (data, was_modified)"""
        if self.attack_mode == "passive":
            return data, False
        elif self.attack_mode == "modify":
            return self.attack_modify_ciphertext(data), True
        elif self.attack_mode == "drop":
            return self.attack_drop(data), False
        elif self.attack_mode == "reorder":
            return self.attack_reorder(data), False
        elif self.attack_mode == "tamper_hmac":
            return self.attack_tamper_hmac(data), True
        elif self.attack_mode == "wrong_round":
            return self.attack_wrong_round(data), True
        elif self.attack_mode == "reflect":
            return self.attack_reflect(data), True
        return data, False
    
    def attack_modify_ciphertext(self, data):
        """Modify bits in ciphertext"""
        if len(data) > 55:
            print("\n" + "="*60)
            print("ATTACK: CIPHERTEXT MODIFICATION")
            print("="*60)
            print("  Action:   Flipping bits in encrypted data")
            print("  Expected: HMAC verification will FAIL")
            print("  Result:   Session should be TERMINATED")
            print("="*60)
            
            data_array = bytearray(data)
            modify_pos = random.randint(23, len(data) - 33)
            original = data_array[modify_pos]
            data_array[modify_pos] ^= 0xFF
            
            print(f"  Modified byte at position {modify_pos}: 0x{original:02X} -> 0x{data_array[modify_pos]:02X}")
            return bytes(data_array)
        return data
    
    def attack_tamper_hmac(self, data):
        """Tamper with HMAC tag"""
        if len(data) > 32:
            print("\n" + "="*60)
            print("ATTACK: HMAC TAMPERING")
            print("="*60)
            print("  Action:   Corrupting the HMAC integrity tag")
            print("  Expected: Integrity check will FAIL")
            print("  Result:   Session should be TERMINATED")
            print("="*60)
            
            data_array = bytearray(data)
            for i in range(32):
                data_array[-(i+1)] ^= 0x01
            
            print("  Corrupted all 32 bytes of HMAC tag")
            return bytes(data_array)
        return data
    
    def attack_wrong_round(self, data):
        """Modify round number"""
        if len(data) > 6:
            data_array = bytearray(data)
            current_round = struct.unpack('!I', data_array[2:6])[0]
            wrong_round = current_round + 5
            
            print("\n" + "="*60)
            print("ATTACK: ROUND NUMBER MODIFICATION")
            print("="*60)
            print(f"  Action:   Changing round {current_round} -> {wrong_round}")
            print("  Expected: Round verification will FAIL")
            print("  Result:   KEY_DESYNC_ERROR, Session TERMINATED")
            print("="*60)
            
            data_array[2:6] = struct.pack('!I', wrong_round)
            return bytes(data_array)
        return data
    
    def attack_drop(self, data):
        """Drop messages randomly"""
        if random.random() < 0.5:
            print("\n" + "="*60)
            print("ATTACK: MESSAGE DROPPING")
            print("="*60)
            print("  Action:   Dropping this message")
            print("  Expected: Communication disrupted")
            print("="*60)
            return None
        return data
    
    def attack_reorder(self, data):
        """Reorder messages"""
        self.message_buffer.append(data)
        
        if len(self.message_buffer) >= 3:
            print("\n" + "="*60)
            print("ATTACK: MESSAGE REORDERING")
            print("="*60)
            print(f"  Action:   Shuffling {len(self.message_buffer)} buffered messages")
            print("  Expected: Out-of-order round numbers detected")
            print("="*60)
            
            random.shuffle(self.message_buffer)
            return self.message_buffer.pop(0)
        
        print(f"  [Buffering message {len(self.message_buffer)}/3 for reorder]")
        return None
    
    def attack_reflect(self, data):
        """Reflect message back to sender (swap direction)"""
        if len(data) > 6:
            data_array = bytearray(data)
            direction = data_array[6]
            
            print("\n" + "="*60)
            print("ATTACK: REFLECTION (Message back to sender)")
            print("="*60)
            print(f"  Action:   Reflecting message back to original sender")
            print(f"  Original direction: {'Client->Server' if direction == 0 else 'Server->Client'}")
            print(f"  New direction:      {'Server->Client' if direction == 0 else 'Client->Server'}")
            print("  Expected: Wrong direction detected, keys don't match")
            print("  Result:   HMAC verification FAIL, Session TERMINATED")
            print("="*60)
            
            # Flip direction byte
            data_array[6] = 1 if direction == 0 else 0
            return bytes(data_array)
        return data
    
    def attack_replay_direct(self):
        """Direct replay attack"""
        if not self.old_packets:
            print("\nREPLAY ATTACK FAILED")
            print("  Reason: No old packets captured yet")
            print("  Fix:    Wait for client to send some messages first")
            return False
        
        if not self.active_server_socket:
            print("\nREPLAY ATTACK FAILED")
            print("  Reason: No active server connection")
            print("  Fix:    Wait for client to connect first")
            return False
        
        try:
            old_packet = random.choice(self.old_packets)
            msg = self.parse_message(old_packet)
            
            print("\n" + "="*60)
            print("EXECUTING REPLAY ATTACK")
            print("="*60)
            print(f"  Action:   Resending old packet from Round {msg['round']}")
            print(f"  Packet:   {msg['opcode_name']} ({msg['size']} bytes)")
            print("  Expected: Server detects duplicate/old round number")
            print("  Result:   Replay DETECTED, Session TERMINATED")
            print("="*60)
            
            self.active_server_socket.sendall(old_packet)
            
            print("[ATTACKER] Old packet sent to server")
            return True
            
        except Exception as e:
            print(f"[ATTACKER] Replay failed: {e}")
            return False
    
    def show_status(self):
        """Show current status"""
        print("\n" + "="*60)
        print("ATTACKER STATUS")
        print("="*60)
        print(f"  Current Mode:   {self.attack_mode.upper()}")
        print(f"  Current Round:  {self.current_round}")
        print(f"  Packets Stored: {len(self.old_packets)}/{self.max_old_packets}")
        print(f"  Total Captured: {len(self.captured_messages)} messages")
        print("="*60)
    
    def interactive_menu(self):
        """Interactive menu"""
        print("\n" + "="*60)
        print("ACTIVE ATTACKER - ATTACK MENU")
        print("="*60)
        print(f"  Current Mode:   {self.attack_mode.upper()}")
        print(f"  Packets Stored: {len(self.old_packets)}/{self.max_old_packets}")
        print(f"  Current Round:  {self.current_round}")
        print("-"*60)
        print("  SELECT AN ATTACK:")
        print("-"*60)
        print("  [1] MODIFY CIPHERTEXT  - Flip bits -> Decryption fails")
        print("  [2] TAMPER HMAC        - Corrupt tag -> Integrity fails")
        print("  [3] WRONG ROUND        - Change round -> Desync detected")
        print("  [4] DROP MESSAGES      - Drop packets -> Communication fails")
        print("  [5] REORDER MESSAGES   - Shuffle order -> Wrong round")
        print("  [6] REPLAY ATTACK      - Resend old packet -> Replay detected")
        print("  [7] REFLECT ATTACK     - Send back to sender -> Wrong keys")
        print("-"*60)
        print("  OTHER OPTIONS:")
        print("-"*60)
        print("  [8] Show Status")
        print("  [9] PASSIVE MODE       - Stop attacking, just forward")
        print("  [0] Exit")
        print("="*60)


def run_interactive_attacker():
    """Run attacker with interactive menu"""
    attacker = MITMAttacker()
    
    print("ATTACKER READY")
    print("  Mode: PASSIVE (forwarding all messages)")
    print("  Waiting for client connection...")
    print("  Use menu below to enable attacks\n")
    
    proxy_thread = threading.Thread(target=attacker.start, daemon=True)
    proxy_thread.start()
    
    time.sleep(1)
    
    while True:
        attacker.interactive_menu()
        choice = input("\nSelect option (0-9): ").strip()
        
        if choice == '1':
            attacker.attack_mode = "modify"
            print("\nCIPHERTEXT MODIFICATION ENABLED")
            print("  All messages will have bits flipped")
            print("  Expected: HMAC fails -> Session terminated")
            
        elif choice == '2':
            attacker.attack_mode = "tamper_hmac"
            print("\nHMAC TAMPERING ENABLED")
            print("  All messages will have corrupted HMACs")
            print("  Expected: Integrity fails -> Session terminated")
            
        elif choice == '3':
            attacker.attack_mode = "wrong_round"
            print("\nROUND MODIFICATION ENABLED")
            print("  All messages will have wrong round numbers")
            print("  Expected: Desync -> KEY_DESYNC_ERROR -> Terminated")
            
        elif choice == '4':
            attacker.attack_mode = "drop"
            print("\nMESSAGE DROPPING ENABLED")
            print("  50% of messages will be dropped")
            print("  Expected: Communication disrupted")
            
        elif choice == '5':
            attacker.attack_mode = "reorder"
            print("\nMESSAGE REORDERING ENABLED")
            print("  Messages will be sent out of order")
            print("  Expected: Wrong round -> Session terminated")
            
        elif choice == '6':
            attacker.attack_replay_direct()
            
        elif choice == '7':
            attacker.attack_mode = "reflect"
            print("\nREFLECT ATTACK ENABLED")
            print("  Messages will be reflected back to sender")
            print("  Expected: Wrong keys used -> HMAC fails -> Terminated")
            
        elif choice == '8':
            attacker.show_status()
            
        elif choice == '9':
            attacker.attack_mode = "passive"
            print("\nPASSIVE MODE ENABLED")
            print("  All messages forwarded without modification")
            
        elif choice == '0':
            print("\nExiting attacker...")
            break
            
        else:
            print("Invalid choice. Please select 0-9.")
        
        time.sleep(0.5)


if __name__ == "__main__":
    print("""
============================================================
               ACTIVE MITM ATTACKER
          Man-in-the-Middle Network Adversary
============================================================

This attacker can perform:
  - Replay attacks      : Resend old captured messages
  - Message modification: Alter ciphertext bits
  - HMAC tampering      : Corrupt integrity tags
  - Round manipulation  : Cause desynchronization
  - Message dropping    : Disrupt communication
  - Message reordering  : Send packets out of order
  - Reflection attack   : Send messages back to sender

Setup Instructions:
  Terminal 1: python server.py
  Terminal 2: python attacks.py       <- You are here
  Terminal 3: python client.py --client-id 1 --port 5001

Expected Results:
  When attack is enabled, the protocol should:
  - DETECT the attack (HMAC fail, wrong round, etc.)
  - TERMINATE the session immediately
  - SHOW ERROR message indicating what was detected

Starting attacker...
""")
    
    run_interactive_attacker()
