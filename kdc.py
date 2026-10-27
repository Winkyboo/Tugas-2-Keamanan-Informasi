import socket
import json
import random
import string
from aes import send_msg, recv_msg, aes_encrypt

def get_valid_key(prompt_text):
    while True:
        key = input(prompt_text)
        if len(key) == 16 and key.isascii():
            return key
        print("[Warning] Master key harus tepat 16 karakter ASCII! Silakan coba lagi.")

def start_kdc(ip='0.0.0.0', port=5000):
    print("=== SERVER KDC ===")
    K_A = get_valid_key("Masukkan Master Key Alice (16 karakter): ")
    K_B = get_valid_key("Masukkan Master Key Bob (16 karakter):   ")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"\n[KDC] Menunggu Alice di {ip}:{port}...")

    while True:
        conn, addr = server.accept()
        print(f"\n[KDC] Koneksi masuk dari {addr}")
        
        try:
            # KDC STEP 1: Menerima request dari Alice (IDA, IDB, N1)
            raw_req = recv_msg(conn)
            if not raw_req:
                continue
            req = json.loads(raw_req.decode())
            print(f"[KDC] Step 1 - Request diterima: {req}")

            # Generate Session Key (Ks) acak 16 karakter ASCII
            session_key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            
            # KDC STEP 2: Membuat Ticket untuk Bob dan Enkripsi pesan untuk Alice
            ticket_payload = json.dumps({"Ks": session_key, "IDA": req['IDA']})
            ticket_bob = aes_encrypt(ticket_payload, K_B)
            
            alice_payload = json.dumps({
                "Ks": session_key,
                "IDB": req['IDB'],
                "N1": req['N1'],
                "Ticket": ticket_bob
            })
            msg_alice = aes_encrypt(alice_payload, K_A)
            
            send_msg(conn, msg_alice.encode())
            print(f"[KDC] Step 2 - Session key & Ticket dikirim ke Alice.")
        except Exception as e:
            print(f"[KDC] Terjadi kesalahan: {e}")
        finally:
            conn.close()

if __name__ == "__main__":
    # ini buat pakai range localhost
    # start_kdc(ip='127.0.0.1', port=5000) 
    start_kdc()