"""
This will generatte a Ed25519 key pair for the user. This will run once for each user and create files that are the users permanent crptographic identity. 

Use: python3 keygen.py <username> 

It'll produce: 
    Private key: <username>_private.key 
    Public key: <username>_public.key 

PS: Used colorama library to make it nicer and easier to read.

"""

import sys
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from colorama import Fore, Style, init

import paths

# Initialize colorama for cross-platform color support
init(autoreset=True)

def user_fingerprint(public_key_bytes: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    full = digest.finalize()
    short = full[:16]
    return ":".join(f"{b:02x}" for b in short)

def delete_old_keys(private_path, public_path) -> bool:
    # prompt user before destroying an existing identity
    while True:
        response = input(f"{Fore.YELLOW}Delete the old key files? (y/n): {Style.RESET_ALL}").strip().lower()
        if response == 'y':
            try:
                if private_path.exists():
                    private_path.unlink()
                if public_path.exists():
                    public_path.unlink()
                print(f"{Fore.GREEN}+ Old key files deleted.{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}X Error deleting files: {e}{Style.RESET_ALL}")
                return False
        elif response == 'n':
            print(f"{Fore.CYAN}Old key files were kept.{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.RED}Please enter y or n.{Style.RESET_ALL}")

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 keygen.py <username>")
        sys.exit(1)

    username = sys.argv[1]

    # Create ~/.encchat/<username>/ if needed, with secure permissions
    paths.ensure_user_dir(username)

    private_path = paths.private_key_path(username)
    public_path = paths.public_key_path(username)

    # make sure that there isnt already a keypair that already exists, and if so refuse to make a new one
    if private_path.exists() or public_path.exists():
        print(f"\n{Fore.RED}X ALERT! There is already keygen files for '{username}' at {paths.user_dir(username)}.{Style.RESET_ALL}")
        if not delete_old_keys(private_path, public_path):
            sys.exit(1)
    
    # generate Ed25519 private key using OS's entropy
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # serializing the bytes
    private_byte = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    public_byte = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    # write to disk, with tight permissions on the private key
    private_path.write_bytes(private_byte)
    os.chmod(private_path, 0o600)

    public_path.write_bytes(public_byte)

    # compute the raw 32 byte public key for the fingerprinting
    raw_public_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

    fp = user_fingerprint(raw_public_key)

    # then we print out everything
    print(f"\n{Fore.GREEN}+ Generated identity for '{username}'{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Key Files:{Style.RESET_ALL}")
    print(f"  * {Fore.YELLOW}Private key:{Style.RESET_ALL} {private_path} {Fore.RED}(keep secret){Style.RESET_ALL}")
    print(f"  * {Fore.YELLOW}Public key:{Style.RESET_ALL} {public_path}")
    print(f"  * {Fore.YELLOW}Fingerprint:{Style.RESET_ALL} {Fore.MAGENTA}{fp}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Important:{Style.RESET_ALL}")
    print(f"  * Share your {Fore.GREEN}fingerprint{Style.RESET_ALL} via a separate channel (phone, in-person) so peers can verify it.")
    print(f"  * {Fore.RED}Never{Style.RESET_ALL} share your {Fore.RED}private key{Style.RESET_ALL} with anyone!\n")

if __name__=="__main__":
    main()