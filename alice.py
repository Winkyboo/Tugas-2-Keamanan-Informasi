# alice.py
import socket
import json
import random
import threading
from aes import send_msg, recv_msg, aes_decrypt, aes_encrypt

def chat_listener(sock, session_key):
    while True:
        try:
            ct_hex = recv_msg(sock).decode()
            if not ct_hex: break
            pt = aes_decrypt(ct_hex, session_key)
            print(f"\n[Bob]: {pt}\n[Alice (You)]: ", end="")
        except Exception:
            print("\n[Alice] Koneksi terputus.")
            break

def start_alice(kdc_ip='127.0.0.1', kdc_port=5000, bob_ip='127.0.0.1', bob_port=6000):
    print("=== ALICE CLIENT ===")
    K_A = input("Masukkan Master Key Alice (harus SAMA dengan input di KDC): ")
    
    # --- FASE 1: Komunikasi dengan KDC ---
    print("\n[Alice] Menghubungi KDC...")
    kdc_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ini buat pakai range localhost
    # kdc_conn.bind(('127.0.0.2', 0))
    kdc_conn.connect((kdc_ip, kdc_port))
    
    N1 = random.randint(1000, 9999)
    req = json.dumps({"IDA": "Alice", "IDB": "Bob", "N1": N1})
    send_msg(kdc_conn, req.encode()) # KDC STEP 1
    
    reply_ct = recv_msg(kdc_conn).decode() # KDC STEP 2
    kdc_conn.close()
    
    reply_data = json.loads(aes_decrypt(reply_ct, K_A))
    if reply_data['N1'] != N1:
        print("[Alice] Error: Nonce N1 KDC tidak cocok!")
        return
        
    session_key = reply_data['Ks']
    ticket_bob = reply_data['Ticket']
    print(f"[Alice] Step 2 - Session Key diterima dari KDC: {session_key}")

    # --- FASE 2: Komunikasi dengan Bob ---
    print("\n[Alice] Menghubungi Bob...")
    bob_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ini buat pakai range localhost
    # bob_conn.bind(('127.0.0.2', 0))
    bob_conn.connect((bob_ip, bob_port))
    
    # KDC STEP 3: Kirim Ticket ke Bob
    send_msg(bob_conn, ticket_bob.encode())
    print("[Alice] Step 3 - Ticket dikirim ke Bob.")

    # KDC STEP 4: Terima Nonce N2 dari Bob
    N2_ct = recv_msg(bob_conn).decode()
    N2 = int(aes_decrypt(N2_ct, session_key))
    
    # KDC STEP 5: Balas N2-1
    reply_ct = aes_encrypt(str(N2 - 1), session_key)
    send_msg(bob_conn, reply_ct.encode())
    print("[Alice] Step 5 - Balasan N2-1 dikirim. Autentikasi Selesai!\n--- MULAI CHAT ---")

    # Mulai thread Chat 2 arah
    threading.Thread(target=chat_listener, args=(bob_conn, session_key), daemon=True).start()
    while True:
        msg = input("[Alice (You)]: ")
        send_msg(bob_conn, aes_encrypt(msg, session_key).encode())

if __name__ == "__main__":
    KDC_IP = '127.0.0.1' 
    BOB_IP = '127.0.0.1'
    # ini buat pakai range localhost
    # start_alice(kdc_ip='127.0.0.1', kdc_port=5000, bob_ip='127.0.0.3', bob_port=6000)
    start_alice(kdc_ip=KDC_IP, kdc_port=5000, bob_ip=BOB_IP, bob_port=6000)