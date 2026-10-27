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
            print(f"\n  [<- Ciphertext Masuk (Hex)]: {ct_hex}")
            pt = aes_decrypt(ct_hex, session_key)
            print(f"[Alice]: {pt}\n[Bob (You)]: ", end="", flush=True)
        except Exception:
            print("\n[Bob] Koneksi terputus.")
            break

def start_bob(ip='0.0.0.0', port=6000):
    print("=== BOB CLIENT ===")
    K_B = input("Masukkan Master Key Bob (harus SAMA dengan input di KDC): ")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((ip, port))
    server.listen(1)
    print(f"\n[Bob] Menunggu Alice di port {port}...")

    conn, addr = server.accept()
    
    # KDC STEP 3: Terima Ticket dari Alice
    ticket_hex = recv_msg(conn).decode()
    ticket_data = json.loads(aes_decrypt(ticket_hex, K_B))
    session_key = ticket_data['Ks']
    print(f"[Bob] Step 3 - Ticket di-decrypt. Session Key: {session_key}")

    # KDC STEP 4: Kirim Nonce N2 (Challenge) ke Alice dienkripsi Ks
    N2 = random.randint(1000, 9999)
    N2_encrypted = aes_encrypt(str(N2), session_key)
    send_msg(conn, N2_encrypted.encode())
    print(f"[Bob] Step 4 - Mengirim Nonce N2 ({N2}) terenkripsi.")

    # KDC STEP 5: Verifikasi balasan N2-1 dari Alice
    reply_hex = recv_msg(conn).decode()
    reply_N2 = int(aes_decrypt(reply_hex, session_key))
    if reply_N2 == N2 - 1:
        print("[Bob] Step 5 - Mutual Authentication Berhasil!\n--- MULAI CHAT ---")
    else:
        print("[Bob] Autentikasi gagal!")
        return

    # Mulai thread Chat 2 arah
    threading.Thread(target=chat_listener, args=(conn, session_key), daemon=True).start()
    while True:
        msg = input("[Bob (You)]: ")
        ct_hex = aes_encrypt(msg, session_key)
        print(f"  [-> Ciphertext Keluar (Hex)]: {ct_hex}")
        send_msg(conn, ct_hex.encode())

if __name__ == "__main__":
    # ini buat pakai range localhost
    # start_bob(ip='127.0.0.3', port=6000)
    start_bob()