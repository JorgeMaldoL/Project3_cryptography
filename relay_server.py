#!/usr/bin/env python3
"""
relay_server.py

Centralized chat relay with public-key directory.

The relay is UNTRUSTED. It just stores and forwards keys/messages but doesn't verify anything.
Clients do TOFU + manual fingerprint verification to check if keys are legit.

Protocol (line-based, UTF-8):

Client -> Server:
    REGISTER <username>
    KEYUPLOAD <base64 PEM of long-term public key>
    GETKEY <username>
    MSG <recipient> <message text...>
    LIST
    QUIT

Server -> Client:
    INFO <text>
    ERROR <text>
    USERLIST <u1> <u2> ...
    FROM <sender> <message text...>
    KEY <username> <base64 PEM>
"""

import socket
import threading
import base64

HOST = "0.0.0.0"
PORT = 5000

# username -> socket (active connections)
clients = {}
# username -> base64 encoded pem key (relay just stores blobs, doesn't verify them)
user_keys = {}

clients_lock = threading.Lock()


def broadcast_info(msg: str):
    # send info message to all connected clients
    with clients_lock:
        for sock in clients.values():
            try:
                sock.sendall(f"INFO {msg}\n".encode("utf-8"))
            except Exception:
                pass


def handle_client(conn: socket.socket, addr):
    # handle a client connection
    username = None
    try:
        conn_file = conn.makefile("r", encoding="utf-8")

        conn.sendall(b"INFO Welcome to the relay server. Please register:\n")
        conn.sendall(b"INFO Use: REGISTER <username>\n")

        line = conn_file.readline()
        if not line:
            return

        line = line.strip()
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or parts[0].upper() != "REGISTER":
            conn.sendall(b"ERROR First command must be: REGISTER <username>\n")
            return

        requested_name = parts[1].strip()
        if not requested_name:
            conn.sendall(b"ERROR Username cannot be empty.\n")
            return

        with clients_lock:
            if requested_name in clients:
                conn.sendall(b"ERROR Username already in use.\n")
                return
            clients[requested_name] = conn
            username = requested_name

        conn.sendall(f"INFO Registered as {username}\n".encode("utf-8"))
        broadcast_info(f"{username} has joined the chat.")

        # main command loop
        for line in conn_file:
            line = line.strip()
            if not line:
                continue

            parts = line.split(maxsplit=2)
            cmd = parts[0].upper()

            if cmd == "LIST":
                with clients_lock:
                    names = " ".join(sorted(clients.keys()))
                conn.sendall(f"USERLIST {names}\n".encode("utf-8"))

            elif cmd == "KEYUPLOAD":
                if len(parts) < 2:
                    conn.sendall(b"ERROR Usage: KEYUPLOAD <base64 PEM>\n")
                    continue
                b64_pem = parts[1].strip()
                # check its valid base64, but don't verify it's a real key (clients do that)
                try:
                    base64.b64decode(b64_pem, validate=True)
                except Exception:
                    conn.sendall(b"ERROR KEYUPLOAD payload is not valid base64.\n")
                    continue
                with clients_lock:
                    user_keys[username] = b64_pem
                conn.sendall(b"INFO Public key registered.\n")

            elif cmd == "GETKEY":
                if len(parts) < 2:
                    conn.sendall(b"ERROR Usage: GETKEY <username>\n")
                    continue
                target = parts[1].strip()
                with clients_lock:
                    b64_pem = user_keys.get(target)
                if b64_pem is None:
                    conn.sendall(f"ERROR No public key for {target}\n".encode("utf-8"))
                else:
                    conn.sendall(f"KEY {target} {b64_pem}\n".encode("utf-8"))

            elif cmd in ("MSG", "INIT", "RESP"):
                if len(parts) < 3:
                    conn.sendall(
                        f"ERROR Usage: {cmd} <recipient> <payload>\n".encode("utf-8")
                    )
                    continue
                recipient = parts[1]
                message_text = parts[2]

                with clients_lock:
                    target_sock = clients.get(recipient)

                if target_sock is None:
                    conn.sendall(
                        f"ERROR No such user: {recipient}\n".encode("utf-8")
                    )
                    continue

                # route to correct wire keyword: msg->from, init->hsinit, resp->hsresp
                out_kw = {"MSG": "FROM", "INIT": "HSINIT", "RESP": "HSRESP"}[cmd]

                try:
                    target_sock.sendall(
                        f"{out_kw} {username} {message_text}\n".encode("utf-8")
                    )
                    conn.sendall(b"INFO Message sent.\n")
                except Exception:
                    conn.sendall(b"ERROR Failed to deliver message.\n")

            elif cmd == "QUIT":
                conn.sendall(b"INFO Goodbye.\n")
                break

            else:
                conn.sendall(b"ERROR Unknown command.\n")

    except Exception as e:
        print(f"[Server] Error with client {addr}: {e}")
    finally:
        if username is not None:
            with clients_lock:
                if clients.get(username) is conn:
                    del clients[username]
                # keep user_keys even after disconnect so others can fetch them
            broadcast_info(f"{username} has left the chat.")

        try:
            conn.close()
        except Exception:
            pass


def main():
    print(f"[Server] Starting relay server on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        print("[Server] Listening for connections...")

        while True:
            conn, addr = s.accept()
            print(f"[Server] New connection from {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


if __name__ == "__main__":
    main()

