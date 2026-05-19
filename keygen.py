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
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform color support
init(autoreset=True)

def user_fingerprint(public_key_bytes: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    full = digest.finalize()
    short = full[:16]
    return ":".join(f"{b:02x}" for b in short)

def delete_old_keys(private_path: str, public_path: str) -> bool:
    """Ask user to confirm deletion of old key files. Returns True if deleted, False if not deleted."""
    while True:
        response = input(f"{Fore.YELLOW}Would you like to delete the old key files? (y/n): {Style.RESET_ALL}").strip().lower()
        if response == 'y':
            try:
                if os.path.exists(private_path):
                    os.remove(private_path)
                if os.path.exists(public_path):
                    os.remove(public_path)
                print(f"{Fore.GREEN}+ Old key files deleted successfully.{Style.RESET_ALL}")
                return True
            except Exception as e:
                print(f"{Fore.RED}X Error deleting files: {e}{Style.RESET_ALL}")
                return False
        elif response == 'n':
            print(f"{Fore.CYAN}Your old key files were not deleted.{Style.RESET_ALL}")
            return False
        else:
            print(f"{Fore.RED}Please only enter y or n.{Style.RESET_ALL}")

def main():
    if len(sys.argv) != 2:
        print("python3 keygen.py <username> ")
        sys.exit(1)
    
    username = sys.argv[1]
    private_path = f"{username}_private.key"
    public_path = f"{username}_public.key"

    # make sure that there isn't already a keypair that already exists and if so refuse to make a new one.

    if os.path.exists(private_path) or os.path.exists(public_path):
        print(f"\n{Fore.RED}X ALERT! There is already keygen files for '{username}'.{Style.RESET_ALL}")
        if not delete_old_keys(private_path, public_path):
            sys.exit(1)
    
    # generate Ed25519 private key using OS's.
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # serializing the bytes.
    private_byte = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption(),)
    public_byte = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,)

    with open(private_path, "wb") as f:
        f.write(private_byte)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f:
        f.write(public_byte)

    # compute the raw 32bytes public key for the fingerprinting
    raw_public_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,)

    fp = user_fingerprint(raw_public_key)

    # then we print out everything
    print(f"\n{Fore.GREEN}+ Generating the identity for '{username}'{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Key Files:{Style.RESET_ALL}")
    print(f"  * {Fore.YELLOW}Private key:{Style.RESET_ALL} {private_path} {Fore.RED}(keep secret){Style.RESET_ALL}")
    print(f"  * {Fore.YELLOW}Public key:{Style.RESET_ALL} {public_path}")
    print(f"  * {Fore.YELLOW}Fingerprint:{Style.RESET_ALL} {Fore.MAGENTA}{fp}{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}Important:{Style.RESET_ALL}")
    print(f"  * You can share the {Fore.GREEN}public key{Style.RESET_ALL} with anyone")
    print(f"  * {Fore.RED}Never{Style.RESET_ALL} share your {Fore.RED}private key{Style.RESET_ALL} with anyone!\n")

if __name__=="__main__":
    main()