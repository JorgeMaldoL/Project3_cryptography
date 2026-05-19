"""
a command-line chat client with a end to end encryption 

run: python3 client.py <username> <server_host> <server_port> 

The client will expect that the user identity key files at ~/.encchat/<username>/ to already exist. Run "python3 keygen.py <username>" first. 
"""

import socket
import threading
import sys
import paths

from cryptography.hazmat.primitives.asymmetric.ed25519 import( Ed25519PrivateKey, Ed25519PublicKey, )
from cryptography.hazmat.primitives import serialization, hashes
from colorama import Fore, Style, init

init(autoreset=True)

def load_private_key(path) -> Ed25519PrivateKey:
    # loads the pem-encoded ed25519 private key from disk
    pem_data = path.read_bytes()
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError(f"{path} not an Ed25519 private key")
    return key

def load_public_key(path) -> Ed25519PublicKey:
    # loads pem-encoded ed25519 public key from disk
    pem_data = path.read_bytes()
    key = serialization.load_pem_public_key(pem_data)
    if not isinstance(key, Ed25519PublicKey): 
        raise ValueError(f"{path} not an Ed25519 public key")
    return key

def fingerprint(public_key: Ed25519PublicKey) -> str:
    # sha-256 fingerprint using ed25519 public key. the first 16 bytes, in hex format
    raw = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    short = digest.finalize()[:16]
    return ":".join(f"{b:02x}" for b in short)

known_peers = {

}

sessions = {

}

def recv_loop(sock: socket.socket): 
    # receives messages from server and prints them
    try:
        conn_file = sock.makefile("r", encoding="utf-8")
        for line in conn_file:
            line = line.rstrip("\n")
            print(f"\n{line}")
            print("> ", end="", flush=True)
    except Exception as e: 
        print(f"\n{Fore.RED}X [system] received error: {e}{Style.RESET_ALL}")
    finally: 
        print(f"\n{Fore.CYAN}* [system] Disconnected from the server.{Style.RESET_ALL}")
        try: 
            sock.close()
        except Exception:
            pass

def send_loop(sock: socket.socket, username: str):
    # reads user inputs and sends them to the server
    try: 
        while True:
            msg = input("> ")
            stripped = msg.strip()

            if stripped.lower() in {"/quit", "quit", "exit"}:
                sock.sendall(b"QUIT\n")
                break

            sock.sendall((stripped + "\n").encode("utf-8"))
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Fore.YELLOW}* [system] exiting...{Style.RESET_ALL}")
        try: 
            sock.sendall(b"QUIT\n")
        except Exception:
            pass
    finally:
        try:
            sock.close()
        except Exception:
            pass

def main():
    if len(sys.argv) != 4:
        print("Usage: python3 client.py <username> <server_host> <server_port>")
        sys.exit(1)

    username = sys.argv[1]
    server_host = sys.argv[2]
    server_port = int(sys.argv[3])

    priv_path = paths.private_key_path(username)
    pub_path = paths.public_key_path(username)

    if not priv_path.exists() or not pub_path.exists():
        print(f"{Fore.RED}X Missing key files for '{username}'.{Style.RESET_ALL}")
        print(f"    Expected: {priv_path}")
        print(f"    Run: python3 keygen.py {username}")
        sys.exit(1)

    # loads the identity that's held for the entire lifetime of the process
    my_private = load_private_key(priv_path)
    my_public = load_public_key(pub_path)
    my_fp = fingerprint(my_public)

    print(f"{Fore.GREEN}+ Loaded identity for '{username}'.{Style.RESET_ALL}")
    print(f"    {Fore.YELLOW}Fingerprint:{Style.RESET_ALL} {Fore.MAGENTA}{my_fp}{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}* Share this fingerprint with peers through a separate channel{Style.RESET_ALL}")
    print(f"    {Fore.CYAN}* so they can verify they're actually talking to you.{Style.RESET_ALL}\n")

    # stashing the module level globals so the functions can reach them
    global MY_USERNAME, MY_PRIVATE, MY_PUBLIC 
    MY_USERNAME = username
    MY_PRIVATE = my_private
    MY_PUBLIC = my_public

    # then we connect to the relay server
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"{Fore.YELLOW}* [system] Connecting to {server_host}:{server_port}...{Style.RESET_ALL}")
    sock.connect((server_host, server_port))
    print(f"{Fore.GREEN}+ [system] Connected.{Style.RESET_ALL}\n")

    # registers with server automatically
    # doing it this way makes sure that the name on the wire matches the identity of the keys just loaded
    sock.sendall(f"Register {username}\n".encode("utf-8"))

    # receiver thread runs in the background and send loop blocks on input
    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()
    send_loop(sock, username)

if __name__ == "__main__":
    main()
