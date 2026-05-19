"""
Ok this is like a bookkeeper that knows where all the file paths go

The user data will live under ~/.encchat/

This is the layout I'm trying to have for the users: 
    ~/.encchat/
        <username>/
            private.key = the user Ed25519 private key 
            public.key = the user Ed25519 public key
        known_peers.json = TOFU (trust on first use) stores the peer_name -> fingerprint + pubkey

"""
import os 
from pathlib import Path

# The root app data ~/.encchat/
APP_DIR = Path.home() / ".encchat"

def user_dir(username: str) -> Path: 
    # return the directory that's holding <username> identity key
    return APP_DIR / username

def private_key_path(username: str) -> Path:
    return user_dir(username) / "private.key"

def public_key_path(username: str) -> Path: 
    return user_dir(username) / "public.key"

def known_peers_path() -> Path:
    # returns the path of the TOFU store
    return APP_DIR / "known_peers.json"

def ensure_user_dir(username: str) -> Path:
    # This'll create a ~/.encchat/<username>/ directory if it doesn't already exist. Then returns the path. Also sets restrictions of permissions of the users dir so other accounts on the same machine aren't able to read it.
    path = user_dir(username)
    path.mkdir(parents=True, exist_ok=True)
    # 0o700 = only the owner can read, write and execute permissions.
    os.chmod(path, 0o700)
    # parent APP_DIR is only the owner
    os.chmod(APP_DIR, 0o700)
    return path
