import socket
import json
import random
import string
from aes import send_msg, recv_msg, aes_encrypt

def start_kdc(ip='0.0.0.0', port=5000):
    print("=== SERVER KDC ===")
    print("Catatan: Master Key harus 16 karakter (contoh: MasterKeyAlice12)")
    K_A = input("Masukkan Master Key Alice: ")
    K_B = input("Masukkan Master Key Bob:   ")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"\n[KDC] Menunggu Alice di {ip}:{port}...")

    while True:
        conn, addr = server.accept()
        print(f"\n[KDC] Koneksi masuk dari {addr}")
        
        try:
            # KDC STEP 1: Menerima request dari Alice (IDA, IDB, N1)
            req = json.loads(recv_msg(conn).decode())
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