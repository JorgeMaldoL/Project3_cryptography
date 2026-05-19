#!/usr/bin/env python3
"""
client.py

Command-line chat client with end-to-end encryption support.

Usage:
    python3 client.py <username> <server_host> <server_port>

Commands once connected:
    /help              show commands
    /myfp              show your fingerprint
    /peers             show known peers and their fingerprints
    /secure <user>     fetch user's public key from relay and run TOFU
    /verify <user>     mark a peer as manually verified
    /quit              exit

    LIST, MSG          raw relay commands (plaintext for now)
"""

import socket
import threading
import sys
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from colorama import Fore, Style, init

import paths
import tofu

init(autoreset=True)


def load_private_key(path) -> Ed25519PrivateKey:
    # loads pem-encoded ed25519 private key from disk
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
    # sha-256 fingerprint (first 16 bytes in hex)
    raw = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(raw)
    short = digest.finalize()[:16]
    return ":".join(f"{b:02x}" for b in short)


def public_key_to_base64_pem(public_key: Ed25519PublicKey) -> str:
    # serialize public key to pem, then base64 encode for sending over wire
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pem).decode("ascii")


# peer username -> Ed25519PublicKey (once accepted via TOFU)
known_peers = {}

# thread coordination for getkey responses
# send_loop sends getkey bob, recv_loop gets the response and sets the event
pending_key_user: str = ""
pending_key_pem: str = ""
pending_key_event = threading.Event()


def recv_loop(sock: socket.socket):
    # receives messages from server and prints them
    # also intercepts KEY responses for /secure flow
    global pending_key_pem
    try:
        conn_file = sock.makefile("r", encoding="utf-8")
        for line in conn_file:
            line = line.rstrip("\n")
            parts = line.split(maxsplit=2)

            # intercept KEY responses for /secure flow
            if len(parts) >= 3 and parts[0] == "KEY":
                target = parts[1]
                payload = parts[2]
                if target == pending_key_user:
                    pending_key_pem = payload
                    pending_key_event.set()
                    continue

            # intercept error for missing keys
            if (line.startswith("ERROR No public key for") and pending_key_user and not pending_key_event.is_set()):
                pending_key_pem = ""
                pending_key_event.set()
                print(f"\n{Fore.RED}{line}{Style.RESET_ALL}")
                print("> ", end="", flush=True)
                continue

            print(f"\n{line}")
            print("> ", end="", flush=True)
    except Exception as e:
        print(f"\n{Fore.RED}X [system] receive error: {e}{Style.RESET_ALL}")
    finally:
        print(f"\n{Fore.CYAN}* [system] disconnected from server{Style.RESET_ALL}")
        try:
            sock.close()
        except Exception:
            pass


def fetch_peer_key(sock: socket.socket, username: str, timeout: float = 5.0):
    # ask relay for username's public key, wait for response
    # returns base64-pem string or none on failure
    global pending_key_user, pending_key_pem
    pending_key_user = username
    pending_key_pem = ""
    pending_key_event.clear()

    sock.sendall(f"GETKEY {username}\n".encode("utf-8"))

    got = pending_key_event.wait(timeout=timeout)
    pending_key_user = ""
    if not got:
        return None
    return pending_key_pem or None


def handle_secure_command(sock: socket.socket, target: str):
    # /secure <target>: fetch peer's key from relay and run TOFU
    print(f"{Fore.CYAN}* fetching public key for '{target}'...{Style.RESET_ALL}")
    b64 = fetch_peer_key(sock, target)
    if b64 is None:
        print(f"{Fore.RED}X could not fetch key for '{target}'{Style.RESET_ALL}")
        return

    try:
        pem_data = base64.b64decode(b64, validate=True)
        key_obj = serialization.load_pem_public_key(pem_data)
        if not isinstance(key_obj, Ed25519PublicKey):
            raise ValueError("not an ed25519 public key")
    except Exception as e:
        print(f"{Fore.RED}X malformed key from relay: {e}{Style.RESET_ALL}")
        return

    incoming_fp = tofu.fingerprint_of_pem(pem_data)
    match = tofu.fingerprint_matches(target, pem_data)

    if match is None:
        # first time seeing this peer, show tofu prompt
        print(f"{Fore.YELLOW}? first time seeing '{target}':{Style.RESET_ALL}")
        print(f"    fingerprint: {Fore.MAGENTA}{incoming_fp}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}verify this with '{target}' over phone/in-person first!{Style.RESET_ALL}")
        ans = input(f"    accept this key? [y/N]: ").strip().lower()
        if ans != "y":
            print(f"{Fore.RED}X rejected. no secure session.{Style.RESET_ALL}")
            return
        tofu.record_peer(target, pem_data)
        known_peers[target] = key_obj
        print(f"{Fore.GREEN}+ stored '{target}' with fingerprint {incoming_fp}{Style.RESET_ALL}")
        print(f"    status: {Fore.YELLOW}unverified{Style.RESET_ALL} (run /verify {target} after confirming)")
        return

    if match is True:
        # same key as before, good
        entry = tofu.get_peer(target)
        status = f"{Fore.GREEN}verified{Style.RESET_ALL}" if entry["verified"] else f"{Fore.YELLOW}unverified (tofu only){Style.RESET_ALL}"
        known_peers[target] = key_obj
        print(f"{Fore.GREEN}+ key for '{target}' matches{Style.RESET_ALL}")
        print(f"    fingerprint: {Fore.MAGENTA}{incoming_fp}{Style.RESET_ALL}")
        print(f"    status: {status}")
        return

    # match is false - fingerprint changed, possible mitm
    entry = tofu.get_peer(target)
    print(f"\n{Fore.RED}{'!' * 60}{Style.RESET_ALL}")
    print(f"{Fore.RED}X WARNING: KEY MISMATCH for '{target}'{Style.RESET_ALL}")
    print(f"    stored:   {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}")
    print(f"    received: {Fore.MAGENTA}{incoming_fp}{Style.RESET_ALL}")
    print(f"    possible mitm attack or {target} regenerated their key")
    print(f"    delete {target} from {paths.known_peers_path()} to override")
    print(f"{Fore.RED}{'!' * 60}{Style.RESET_ALL}\n")


def handle_peers_command():
    # show all known peers and their fingerprints
    store = tofu.load_store()
    if not store:
        print(f"{Fore.YELLOW}* no known peers yet{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}Known peers:{Style.RESET_ALL}")
    for name, entry in store.items():
        status = f"{Fore.GREEN}verified{Style.RESET_ALL}" if entry["verified"] else f"{Fore.YELLOW}unverified{Style.RESET_ALL}"
        print(f"  * {name:12} {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}  [{status}]  {entry['first_seen']}")


def handle_verify_command(target: str):
    # mark a peer as verified after checking fingerprint manually
    entry = tofu.get_peer(target)
    if entry is None:
        print(f"{Fore.RED}X no stored key for '{target}'. run /secure {target} first{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}Stored fingerprint for '{target}':{Style.RESET_ALL}")
    print(f"    {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}confirm out-of-band (phone/in-person) that this matches what {target} sees{Style.RESET_ALL}")
    ans = input(f"does it match? [y/N]: ").strip().lower()
    if ans == "y":
        tofu.mark_verified(target)
        print(f"{Fore.GREEN}+ '{target}' marked as verified{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}* verification not confirmed{Style.RESET_ALL}")


def handle_myfp_command(my_fp: str, username: str):
    # show your own fingerprint
    print(f"{Fore.CYAN}Your fingerprint:{Style.RESET_ALL}")
    print(f"    {Fore.MAGENTA}{my_fp}{Style.RESET_ALL}")
    print(f"    share this with peers so they can /verify {username} after /secure {username}")


def handle_help_command():
    # show available commands
    print(f"{Fore.CYAN}Commands:{Style.RESET_ALL}")
    print(f"  /help              show this help")
    print(f"  /myfp              show your fingerprint")
    print(f"  /peers             list known peers and fingerprints")
    print(f"  /secure <user>     fetch user's public key and run tofu")
    print(f"  /verify <user>     mark a peer as manually verified")
    print(f"  /quit              exit")
    print(f"  LIST               ask relay who's online")
    print(f"  MSG <user> <text>  send plaintext message")


def send_loop(sock: socket.socket, username: str, my_fp: str):
    # reads user input and sends commands to server
    try:
        while True:
            msg = input("> ")
            stripped = msg.strip()
            if not stripped:
                continue

            low = stripped.lower()

            if low in {"/quit", "quit", "exit"}:
                sock.sendall(b"QUIT\n")
                break

            if low == "/help":
                handle_help_command()
                continue

            if low == "/myfp":
                handle_myfp_command(my_fp, username)
                continue

            if low == "/peers":
                handle_peers_command()
                continue

            if low.startswith("/secure"):
                parts = stripped.split(maxsplit=1)
                if len(parts) != 2:
                    print(f"{Fore.RED}usage: /secure <user>{Style.RESET_ALL}")
                    continue
                handle_secure_command(sock, parts[1].strip())
                continue

            if low.startswith("/verify"):
                parts = stripped.split(maxsplit=1)
                if len(parts) != 2:
                    print(f"{Fore.RED}usage: /verify <user>{Style.RESET_ALL}")
                    continue
                handle_verify_command(parts[1].strip())
                continue

            # send as raw relay command
            sock.sendall((stripped + "\n").encode("utf-8"))
    except (EOFError, KeyboardInterrupt):
        print("\n[system] exiting...")
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
        print("usage: python3 client.py <username> <server_host> <server_port>")
        sys.exit(1)

    username = sys.argv[1]
    server_host = sys.argv[2]
    server_port = int(sys.argv[3])

    priv_path = paths.private_key_path(username)
    pub_path = paths.public_key_path(username)

    if not priv_path.exists() or not pub_path.exists():
        print(f"{Fore.RED}X missing key files for '{username}'${Style.RESET_ALL}")
        print(f"    expected: {priv_path}")
        print(f"    run: python3 keygen.py {username}")
        sys.exit(1)

    my_private = load_private_key(priv_path)
    my_public = load_public_key(pub_path)
    my_fp = fingerprint(my_public)

    print(f"{Fore.GREEN}+ loaded identity for '{username}'{Style.RESET_ALL}")
    print(f"    fingerprint: {Fore.MAGENTA}{my_fp}{Style.RESET_ALL}")
    print(f"    type /help for commands\n")

    global MY_USERNAME, MY_PRIVATE, MY_PUBLIC
    MY_USERNAME = username
    MY_PRIVATE = my_private
    MY_PUBLIC = my_public

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[system] connecting to {server_host}:{server_port}...")
    sock.connect((server_host, server_port))
    print("[system] connected\n")

    # register with relay
    sock.sendall(f"REGISTER {username}\n".encode("utf-8"))

    # upload public key so others can fetch it
    b64_pem = public_key_to_base64_pem(my_public)
    sock.sendall(f"KEYUPLOAD {b64_pem}\n".encode("utf-8"))

    t = threading.Thread(target=recv_loop, args=(sock,), daemon=True)
    t.start()
    send_loop(sock, username, my_fp)


if __name__ == "__main__":
    main()
