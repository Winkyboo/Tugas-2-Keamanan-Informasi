import socket
import json
import random
import threading
from aes import send_msg, recv_msg, aes_decrypt, aes_encrypt

def get_valid_key(prompt_text):
    while True:
        key = input(prompt_text)
        if len(key) == 16 and key.isascii():
            return key
        print("[Warning] Master key harus tepat 16 karakter ASCII! Silakan coba lagi.")

def chat_listener(sock, session_key):
    while True:
        try:
            raw = recv_msg(sock)
            if not raw: break
            ct_hex = raw.decode()
            print(f"\n  [<- Ciphertext Masuk (Hex)]: {ct_hex}")
            pt = aes_decrypt(ct_hex, session_key)
            print(f"[Bob]: {pt}\n[Alice (You)]: ", end="", flush=True)
        except ValueError as e:
            print(f"\n[Error Dekripsi]: {e}")
            print("[Alice (You)]: ", end="", flush=True)
        except Exception:
            print("\n[Alice] Koneksi terputus.")
            break

def start_alice(kdc_ip='127.0.0.1', kdc_port=5000, bob_ip='127.0.0.1', bob_port=6000):
    print("=== ALICE CLIENT ===")
    K_A = get_valid_key("Masukkan Master Key Alice (16 karakter): ")
    
    # --- FASE 1: Komunikasi dengan KDC ---
    print("\n[Alice] Menghubungi KDC...")
    kdc_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ini buat pakai range localhost
    # kdc_conn.bind(('127.0.0.2', 0))
    try:
        kdc_conn.connect((kdc_ip, kdc_port))
    except Exception as e:
        print(f"[Alice] Gagal terhubung ke KDC: {e}")
        return
    
    N1 = random.randint(1000, 9999)
    req = json.dumps({"IDA": "Alice", "IDB": "Bob", "N1": N1})
    send_msg(kdc_conn, req.encode()) # KDC STEP 1
    
    reply_raw = recv_msg(kdc_conn) # KDC STEP 2
    kdc_conn.close()
    
    if not reply_raw:
        print("[Alice] Tidak ada respons dari KDC.")
        return
    
    reply_ct = reply_raw.decode()
    try:
        decrypted_reply = aes_decrypt(reply_ct, K_A)
        reply_data = json.loads(decrypted_reply)
    except Exception:
        print("[Alice] Error: Master key Alice tidak cocok dengan KDC!")
        return

    if reply_data.get('N1') != N1:
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
    try:
        bob_conn.connect((bob_ip, bob_port))
    except Exception as e:
        print(f"[Alice] Gagal terhubung ke Bob: {e}")
        return
    
    # KDC STEP 3: Kirim Ticket ke Bob
    send_msg(bob_conn, ticket_bob.encode())
    print("[Alice] Step 3 - Ticket dikirim ke Bob.")

    # KDC STEP 4: Terima Nonce N2 dari Bob
    N2_raw = recv_msg(bob_conn)
    if not N2_raw:
        print("[Alice] Bob memutuskan koneksi.")
        return
    N2_ct = N2_raw.decode()
    try:
        N2 = int(aes_decrypt(N2_ct, session_key))
    except Exception:
        print("[Alice] Error: Gagal dekripsi Nonce N2 (Session Key tidak cocok).")
        return
    
    # KDC STEP 5: Balas N2-1
    reply_ct = aes_encrypt(str(N2 - 1), session_key)
    send_msg(bob_conn, reply_ct.encode())
    print("[Alice] Step 5 - Balasan N2-1 dikirim. Autentikasi Selesai!\n--- MULAI CHAT ---")

    # Mulai thread Chat 2 arah
    threading.Thread(target=chat_listener, args=(bob_conn, session_key), daemon=True).start()
    while True:
        msg = input("[Alice (You)]: ")
        if not msg.isascii():
            print("[Error] Pesan mengandung karakter non-ASCII (emoji/simbol tak didukung)!")
            continue
        ct_hex = aes_encrypt(msg, session_key)
        print(f"  [-> Ciphertext Keluar (Hex)]: {ct_hex}")
        send_msg(bob_conn, ct_hex.encode())

if __name__ == "__main__":
    KDC_IP = '127.0.0.1' 
    BOB_IP = '127.0.0.1'
    # ini buat pakai range localhost
    # start_alice(kdc_ip='127.0.0.1', kdc_port=5000, bob_ip='127.0.0.3', bob_port=6000)
    start_alice(kdc_ip=KDC_IP, kdc_port=5000, bob_ip=BOB_IP, bob_port=6000)