#!/usr/bin/env python3
"""
client.py

command-line e2e-encrypted chat client.

usage:
    python3 client.py <username> <server_host> <server_port>

commands:
    /help              show help
    /myfp              show your fingerprint
    /peers             list known peers
    /sessions          list active secure sessions
    /secure <user>     tofu + handshake, establish session
    /verify <user>     mark a peer as manually verified
    /quit              exit

    LIST, MSG          raw relay commands
"""

import socket
import threading
import sys
import base64

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from colorama import Fore, Style, init

import paths
import tofu
import cryptography_session as cs

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
    return ":".join(f"{b:02x}" for b in digest.finalize()[:16])


def public_key_to_base64_pem(public_key: Ed25519PublicKey) -> str:
    # serialize public key to pem then base64 encode for wire
    pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pem).decode("ascii")


def load_peer_long_term_key(username: str) -> Ed25519PublicKey:
    # get a tofu'd peer's long-term key object
    entry = tofu.get_peer(username)
    if entry is None:
        raise KeyError(f"no tofu record for {username}")
    key = serialization.load_pem_public_key(entry["public_key_pem"].encode("utf-8"))
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError(f"stored key for {username} is not ed25519")
    return key


def encrypt_message(session: dict, plaintext: str) -> str:
    # chacha20-poly1305: nonce = 12-byte little-endian counter
    nonce = session["send_counter"].to_bytes(12, "little")
    ct = ChaCha20Poly1305(session["send_key"]).encrypt(nonce, plaintext.encode("utf-8"), None)
    session["send_counter"] += 1
    return base64.b64encode(ct).decode("ascii")


def decrypt_message(session: dict, blob_b64: str) -> str:
    # raises InvalidTag on auth failure (tampering / wrong key / bad counter)
    nonce = session["recv_counter"].to_bytes(12, "little")
    ct = base64.b64decode(blob_b64)
    plaintext = ChaCha20Poly1305(session["recv_key"]).decrypt(nonce, ct, None)
    session["recv_counter"] += 1
    return plaintext.decode("utf-8")


# peer username -> Ed25519PublicKey (in-process cache of tofu'd keys)
known_peers = {}

# peer username -> session dict
sessions = {}

# in-flight handshakes i started: peer username -> X25519PrivateKey
pending_handshakes = {}

# thread coordination for getkey responses
pending_key_user: str = ""
pending_key_pem: str = ""
pending_key_event = threading.Event()

# thread coordination for handshake responses
pending_handshake_user: str = ""
pending_handshake_payload: str = ""
pending_handshake_event = threading.Event()

state_lock = threading.Lock()


def recv_loop(sock: socket.socket, my_username: str, my_long_term_priv: Ed25519PrivateKey):
    # receives messages from server, intercepts KEY/HSINIT/HSRESP
    global pending_key_pem, pending_handshake_payload
    try:
        conn_file = sock.makefile("r", encoding="utf-8")
        for line in conn_file:
            line = line.rstrip("\n")
            parts = line.split(maxsplit=2)
            if not parts:
                continue

            # intercept KEY responses for /secure flow
            if len(parts) >= 3 and parts[0] == "KEY":
                if parts[1] == pending_key_user:
                    pending_key_pem = parts[2]
                    pending_key_event.set()
                    continue

            # intercept error for missing keys
            if line.startswith("ERROR No public key for ") and pending_key_user and not pending_key_event.is_set():
                pending_key_pem = ""
                pending_key_event.set()
                print(f"\n{Fore.RED}{line}{Style.RESET_ALL}")
                print("> ", end="", flush=True)
                continue

            # incoming handshake init from peer
            if len(parts) >= 3 and parts[0] == "HSINIT":
                _handle_incoming_hsinit(sock, my_username, my_long_term_priv, parts[1], parts[2])
                print("> ", end="", flush=True)
                continue

            # handshake response to one we initiated
            if len(parts) >= 3 and parts[0] == "HSRESP":
                if parts[1] == pending_handshake_user:
                    pending_handshake_payload = parts[2]
                    pending_handshake_event.set()
                    continue

            # decrypt FROM messages from peers with an active session
            if len(parts) >= 3 and parts[0] == "FROM":
                sender = parts[1]
                with state_lock:
                    session = sessions.get(sender)
                if session is not None:
                    try:
                        plaintext = decrypt_message(session, parts[2])
                        print(f"\nFROM {sender} {plaintext}")
                    except Exception:
                        print(f"\n{Fore.RED}X [system] TAMPER ALERT: message from '{sender}' failed authentication — possible tampering or corruption!{Style.RESET_ALL}")
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


def _handle_incoming_hsinit(sock: socket.socket, my_username: str, my_long_term_priv: Ed25519PrivateKey, sender: str, payload_b64: str):
    # someone sent us hsinit - verify, derive keys, send hsresp. we're the responder.
    print(f"\n{Fore.CYAN}* incoming handshake from '{sender}'...{Style.RESET_ALL}")

    try:
        peer_lt_pub = load_peer_long_term_key(sender)
    except KeyError:
        print(f"{Fore.RED}X no tofu record for '{sender}'. run /secure {sender} first{Style.RESET_ALL}")
        return

    try:
        payload = cs.parse_handshake_payload(payload_b64)
    except ValueError as e:
        print(f"{Fore.RED}X bad handshake payload: {e}{Style.RESET_ALL}")
        return

    if payload["from"] != sender or payload["to"] != my_username:
        print(f"{Fore.RED}X handshake envelope mismatch. aborting.{Style.RESET_ALL}")
        return

    if not cs.verify_ephemeral(peer_lt_pub, sender=sender, recipient=my_username,
                                ephemeral_pub_bytes=payload["epk"], signature=payload["sig"]):
        print(f"{Fore.RED}X signature on incoming handshake is INVALID. possible mitm. aborting.{Style.RESET_ALL}")
        return

    my_eph_priv, my_eph_pub = cs.generate_ephemeral_keypair()
    my_sig = cs.sign_ephemeral(my_long_term_priv, sender=my_username, recipient=sender, ephemeral_pub_bytes=my_eph_pub)

    peer_eph_pub = cs.x25519_pub_from_bytes(payload["epk"])
    k_init_to_resp, k_resp_to_init = cs.derive_session_keys(
        my_ephemeral_priv=my_eph_priv, peer_ephemeral_pub=peer_eph_pub,
        initiator=sender, responder=my_username,
    )

    # responder: send = responder->initiator, recv = initiator->responder
    with state_lock:
        sessions[sender] = cs.new_session(send_key=k_resp_to_init, recv_key=k_init_to_resp)

    resp_payload = cs.make_handshake_payload(sender=my_username, recipient=sender,
                                              ephemeral_pub_bytes=my_eph_pub, signature=my_sig)
    sock.sendall(f"RESP {sender} {resp_payload}\n".encode("utf-8"))
    print(f"{Fore.GREEN}+ secure session with '{sender}' established (messages are now encrypted){Style.RESET_ALL}")


def fetch_peer_key(sock: socket.socket, username: str, timeout: float = 5.0):
    # ask relay for username's public key, wait for response
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


def tofu_peer(sock: socket.socket, target: str) -> bool:
    # run tofu dance for target, returns true if we have a trusted record
    print(f"{Fore.CYAN}* fetching public key for '{target}'...{Style.RESET_ALL}")
    b64 = fetch_peer_key(sock, target)
    if b64 is None:
        print(f"{Fore.RED}X could not fetch key for '{target}'{Style.RESET_ALL}")
        return False

    try:
        pem_data = base64.b64decode(b64, validate=True)
        key_obj = serialization.load_pem_public_key(pem_data)
        if not isinstance(key_obj, Ed25519PublicKey):
            raise ValueError("not an ed25519 public key")
    except Exception as e:
        print(f"{Fore.RED}X malformed key from relay: {e}{Style.RESET_ALL}")
        return False

    incoming_fp = tofu.fingerprint_of_pem(pem_data)
    match = tofu.fingerprint_matches(target, pem_data)

    if match is None:
        print(f"{Fore.YELLOW}? first time seeing '{target}':{Style.RESET_ALL}")
        print(f"    fingerprint: {Fore.MAGENTA}{incoming_fp}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}verify this with '{target}' over phone/in-person first!{Style.RESET_ALL}")
        ans = input(f"    accept this key? [y/N]: ").strip().lower()
        if ans != "y":
            print(f"{Fore.RED}X rejected.{Style.RESET_ALL}")
            return False
        tofu.record_peer(target, pem_data)
        known_peers[target] = key_obj
        print(f"{Fore.GREEN}+ stored '{target}' (status: {Fore.YELLOW}unverified{Fore.GREEN}){Style.RESET_ALL}")
        return True

    if match is True:
        known_peers[target] = key_obj
        print(f"{Fore.GREEN}+ key for '{target}' matches stored fingerprint{Style.RESET_ALL}")
        return True

    # mismatch - possible mitm
    entry = tofu.get_peer(target)
    print(f"\n{Fore.RED}{'!' * 60}{Style.RESET_ALL}")
    print(f"{Fore.RED}X WARNING: KEY MISMATCH for '{target}'{Style.RESET_ALL}")
    print(f"    stored:   {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}")
    print(f"    received: {Fore.MAGENTA}{incoming_fp}{Style.RESET_ALL}")
    print(f"    delete {target} from {paths.known_peers_path()} to override")
    print(f"{Fore.RED}{'!' * 60}{Style.RESET_ALL}\n")
    return False


def handle_secure_command(sock: socket.socket, my_username: str, my_long_term_priv: Ed25519PrivateKey, target: str):
    # /secure <target>: tofu then run handshake as initiator
    if target == my_username:
        print(f"{Fore.RED}X can't /secure yourself{Style.RESET_ALL}")
        return

    if not tofu_peer(sock, target):
        return

    with state_lock:
        if target in sessions:
            print(f"{Fore.YELLOW}* already have a secure session with '{target}'{Style.RESET_ALL}")
            return

    my_eph_priv, my_eph_pub = cs.generate_ephemeral_keypair()
    my_sig = cs.sign_ephemeral(my_long_term_priv, sender=my_username, recipient=target, ephemeral_pub_bytes=my_eph_pub)
    payload = cs.make_handshake_payload(sender=my_username, recipient=target,
                                         ephemeral_pub_bytes=my_eph_pub, signature=my_sig)

    # arm wait before sending to avoid race
    global pending_handshake_user, pending_handshake_payload
    pending_handshake_user = target
    pending_handshake_payload = ""
    pending_handshake_event.clear()
    with state_lock:
        pending_handshakes[target] = my_eph_priv

    print(f"{Fore.CYAN}* initiating handshake with '{target}'...{Style.RESET_ALL}")
    sock.sendall(f"INIT {target} {payload}\n".encode("utf-8"))

    got = pending_handshake_event.wait(timeout=10.0)
    pending_handshake_user = ""

    if not got:
        print(f"{Fore.RED}X handshake timed out (no response from '{target}'){Style.RESET_ALL}")
        with state_lock:
            pending_handshakes.pop(target, None)
        return

    try:
        resp = cs.parse_handshake_payload(pending_handshake_payload)
    except ValueError as e:
        print(f"{Fore.RED}X bad hsresp payload: {e}{Style.RESET_ALL}")
        return

    if resp["from"] != target or resp["to"] != my_username:
        print(f"{Fore.RED}X hsresp envelope mismatch. aborting.{Style.RESET_ALL}")
        return

    peer_lt_pub = load_peer_long_term_key(target)
    if not cs.verify_ephemeral(peer_lt_pub, sender=target, recipient=my_username,
                                ephemeral_pub_bytes=resp["epk"], signature=resp["sig"]):
        print(f"{Fore.RED}X signature on hsresp is INVALID. possible mitm. aborting.{Style.RESET_ALL}")
        return

    peer_eph_pub = cs.x25519_pub_from_bytes(resp["epk"])
    k_init_to_resp, k_resp_to_init = cs.derive_session_keys(
        my_ephemeral_priv=my_eph_priv, peer_ephemeral_pub=peer_eph_pub,
        initiator=my_username, responder=target,
    )

    with state_lock:
        sessions[target] = cs.new_session(send_key=k_init_to_resp, recv_key=k_resp_to_init)
        pending_handshakes.pop(target, None)

    print(f"{Fore.GREEN}+ secure session with '{target}' established (messages are now encrypted){Style.RESET_ALL}")


def handle_peers_command():
    # show all tofu'd peers and their fingerprints
    store = tofu.load_store()
    if not store:
        print(f"{Fore.YELLOW}* no known peers yet{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}known peers:{Style.RESET_ALL}")
    for name, entry in store.items():
        status = f"{Fore.GREEN}verified{Style.RESET_ALL}" if entry["verified"] else f"{Fore.YELLOW}unverified{Style.RESET_ALL}"
        print(f"  * {name:12} {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}  [{status}]  {entry['first_seen']}")


def handle_sessions_command():
    # show all active secure sessions
    with state_lock:
        if not sessions:
            print(f"{Fore.YELLOW}* no active secure sessions{Style.RESET_ALL}")
            return
        print(f"{Fore.CYAN}active sessions:{Style.RESET_ALL}")
        for name, s in sessions.items():
            print(f"  * {name:12}  established {s['established_at']}  sent={s['send_counter']}  received={s['recv_counter']}")


def handle_verify_command(target: str):
    # mark a peer as verified after checking fingerprint manually
    entry = tofu.get_peer(target)
    if entry is None:
        print(f"{Fore.RED}X no stored key for '{target}'. run /secure {target} first{Style.RESET_ALL}")
        return
    print(f"{Fore.CYAN}stored fingerprint for '{target}':{Style.RESET_ALL}")
    print(f"    {Fore.MAGENTA}{entry['fingerprint']}{Style.RESET_ALL}")
    ans = input(f"does it match what {target} told you out-of-band? [y/N]: ").strip().lower()
    if ans == "y":
        tofu.mark_verified(target)
        print(f"{Fore.GREEN}+ '{target}' marked as verified{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}* status unchanged{Style.RESET_ALL}")


def handle_myfp_command(my_fp: str, username: str):
    # show your own fingerprint
    print(f"{Fore.CYAN}your fingerprint:{Style.RESET_ALL}")
    print(f"    {Fore.MAGENTA}{my_fp}{Style.RESET_ALL}")
    print(f"    share this with peers so they can /verify {username} after /secure {username}")


def handle_help_command():
    # show available commands
    print(f"{Fore.CYAN}commands:{Style.RESET_ALL}")
    print(f"  /help              show this help")
    print(f"  /myfp              show your fingerprint")
    print(f"  /peers             list tofu'd peers and fingerprints")
    print(f"  /sessions          list active secure sessions")
    print(f"  /secure <user>     tofu + handshake, establish session")
    print(f"  /verify <user>     mark a peer as manually verified")
    print(f"  /quit              exit")
    print(f"  LIST               ask relay who's online")
    print(f"  MSG <user> <text>  send encrypted message (requires /secure <user> first)")


def send_loop(sock: socket.socket, username: str, my_fp: str, my_long_term_priv: Ed25519PrivateKey):
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
                handle_help_command(); continue
            if low == "/myfp":
                handle_myfp_command(my_fp, username); continue
            if low == "/peers":
                handle_peers_command(); continue
            if low == "/sessions":
                handle_sessions_command(); continue
            if low.startswith("/secure"):
                parts = stripped.split(maxsplit=1)
                if len(parts) != 2:
                    print(f"{Fore.RED}usage: /secure <user>{Style.RESET_ALL}")
                    continue
                handle_secure_command(sock, username, my_long_term_priv, parts[1].strip())
                continue
            if low.startswith("/verify"):
                parts = stripped.split(maxsplit=1)
                if len(parts) != 2:
                    print(f"{Fore.RED}usage: /verify <user>{Style.RESET_ALL}")
                    continue
                handle_verify_command(parts[1].strip()); continue

            # encrypt MSG to peers with an active session
            parts = stripped.split(maxsplit=2)
            if parts[0].upper() == "MSG" and len(parts) == 3:
                peer, text = parts[1], parts[2]
                with state_lock:
                    session = sessions.get(peer)
                if session is None:
                    print(f"{Fore.RED}X no secure session with '{peer}'. run /secure {peer} first{Style.RESET_ALL}")
                    continue
                blob = encrypt_message(session, text)
                sock.sendall(f"MSG {peer} {blob}\n".encode("utf-8"))
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
        print(f"{Fore.RED}X missing key files for '{username}'{Style.RESET_ALL}")
        print(f"    run: python3 keygen.py {username}")
        sys.exit(1)

    my_private = load_private_key(priv_path)
    my_public = load_public_key(pub_path)
    my_fp = fingerprint(my_public)

    print(f"{Fore.GREEN}+ loaded identity for '{username}'{Style.RESET_ALL}")
    print(f"    fingerprint: {Fore.MAGENTA}{my_fp}{Style.RESET_ALL}")
    print(f"    type /help for commands\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[system] connecting to {server_host}:{server_port}...")
    sock.connect((server_host, server_port))
    print("[system] connected\n")

    sock.sendall(f"REGISTER {username}\n".encode("utf-8"))
    b64_pem = public_key_to_base64_pem(my_public)
    sock.sendall(f"KEYUPLOAD {b64_pem}\n".encode("utf-8"))

    t = threading.Thread(target=recv_loop, args=(sock, username, my_private), daemon=True)
    t.start()
    send_loop(sock, username, my_fp, my_private)


if __name__ == "__main__":
    main()
