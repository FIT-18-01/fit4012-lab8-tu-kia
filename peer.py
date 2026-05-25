import os
import socket
import threading
from pathlib import Path

from secure_transfer_utils import (
    build_sender_payload,
    load_public_key,
    load_private_key,
    open_receiver_payload,
    recv_secure_packet,
    sha256_digest,
)

# Config from env
HOST = os.getenv("PEER_HOST", "0.0.0.0")
DATA_PORT = int(os.getenv("DATA_PORT", os.getenv("PORT", "6000")))
OWN_PRIVATE_KEY = os.getenv("OWN_PRIVATE_KEY", "keys/receiver_private.pem")
TIMEOUT = float(os.getenv("SOCKET_TIMEOUT", "10"))
DEFAULT_PEER_PUB = os.getenv("DEFAULT_PEER_PUBLIC", "keys/receiver_public.pem")
SENDER_LOG_FILE = os.getenv("SENDER_LOG_FILE", "")
RECEIVER_LOG_FILE = os.getenv("RECEIVER_LOG_FILE", "")
SAMPLE_INPUT = "sample_input.txt"


def send_packet(host: str, port: int, packet: bytes, timeout: float = TIMEOUT) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(packet)


def write_log(path: str, lines: list) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def handle_conn(conn, addr, own_priv):
    with conn:
        conn.settimeout(TIMEOUT)
        print(f"[+] Received connection from {addr[0]}:{addr[1]}")
        try:
            packet = recv_secure_packet(conn)
        except Exception as e:
            print(f"[!] Error receiving packet: {e}")
            return
        try:
            plaintext, ok = open_receiver_payload(packet, own_priv)
        except Exception as e:
            print(f"[!] Error processing packet: {e}")
            return
        calculated_hash = sha256_digest(plaintext)
        text = plaintext.decode("utf-8", errors="replace")
        lines = [
            f"[+] Received connection from {addr[0]}:{addr[1]}",
            f"[+] Plaintext length: {len(plaintext)} bytes",
            f"[+] SHA-256: {calculated_hash.hex()}",
            f"[+] Integrity OK: {ok}",
            f"[+] Message: {text}",
        ]
        print("----------------- Incoming message -----------------")
        print(f"From: {addr[0]}:{addr[1]}")
        print(text)
        print(f"Integrity OK: {ok}")
        print("----------------------------------------------------")
        if RECEIVER_LOG_FILE:
            write_log(RECEIVER_LOG_FILE, lines)


def server_loop(host: str, port: int, own_priv):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(5)
        print(f"[*] Listening on {host}:{port}")
        while True:
            try:
                conn, addr = server.accept()
            except Exception:
                continue
            t = threading.Thread(target=handle_conn, args=(conn, addr, own_priv), daemon=True)
            t.start()


def interactive_loop(own_priv):
    print("Type 'send' to send a message, 'quit' to exit.")
    while True:
        cmd = input("> ").strip().lower()
        if cmd in ("q", "quit", "exit"):
            print("Exiting.")
            return
        if cmd in ("s", "send"):
            peer_ip = input("Peer IP: ").strip()
            if not peer_ip:
                print("Peer IP required.")
                continue
            peer_port_str = input(f"Peer port [{DATA_PORT}]: ").strip()
            peer_port = int(peer_port_str) if peer_port_str else DATA_PORT
            peer_pub = input(f"Peer public key path [{DEFAULT_PEER_PUB}]: ").strip() or DEFAULT_PEER_PUB
            if not Path(peer_pub).exists():
                print(f"Public key not found: {peer_pub}")
                continue
            message = input("Message (empty to use sample_input.txt): ")
            if not message:
                if Path(SAMPLE_INPUT).exists():
                    plaintext = Path(SAMPLE_INPUT).read_bytes()
                    print(f"[+] Using {SAMPLE_INPUT} as message")
                else:
                    print("No sample_input.txt found and no message entered.")
                    continue
            else:
                plaintext = message.encode("utf-8")

            try:
                peer_pub_key = load_public_key(peer_pub)
                packet, _des_key, _cipher_with_iv, plaintext_hash = build_sender_payload(plaintext, peer_pub_key)
                send_packet(peer_ip, peer_port, packet)
                print("[+] Sent message.")
                if SENDER_LOG_FILE:
                    lines = [
                        f"[+] Sent message to {peer_ip}:{peer_port}",
                        f"[+] Peer public key: {peer_pub}",
                        f"[+] Plaintext length: {len(plaintext)} bytes",
                        f"[+] SHA-256: {plaintext_hash.hex()}",
                    ]
                    write_log(SENDER_LOG_FILE, lines)
            except Exception as e:
                print(f"[!] Failed to send: {e}")
        else:
            print("Commands: send, quit")


def main():
    own_priv = load_private_key(OWN_PRIVATE_KEY)
    # start server thread
    server_thread = threading.Thread(target=server_loop, args=(HOST, DATA_PORT, own_priv), daemon=True)
    server_thread.start()

    # interactive prompt in main thread
    try:
        interactive_loop(own_priv)
    except KeyboardInterrupt:
        print("Interrupted, exiting.")


if __name__ == "__main__":
    main()
