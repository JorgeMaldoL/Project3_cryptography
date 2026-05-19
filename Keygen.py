"""
This will generatte a Ed25519 key pair for the user. This will run once for each user and create files that are the users permanent crptographic identity. 

Use: python3 keygen.py <username> 

It'll produce: 
    Private key: <username>_private.key 
    Public key: <username>_public.key 

"""

import sys
import os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes

def user_fingerprint(public_key_bytes: bytes) -> str:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    full = digest.finalize()
    short = full[:16]
    return ":".join(f"{b:02x}" for b in short)

def main(): 
    if len(sys.argv) != 2 : 
        print("python3 keygen.py <username> ")
        sys.exit(1)
    
    username = sys.argv[1]
    private_path = f"{username}_private.key"
    public_path = f"{username}_public.key"

    #make sure that there isn't already a keypair that already exists and if so refuse to make a new one. 

    if os.path.exists(private_path) or os.path.exists(public_path):
        print(f"ALERT! There is already keygen files for '{username}'. \nIf you need new files just delete the old ones first.\nWrite this in your terminal -> CMD: rm {private_path} {public_path}")
        sys.exit(1)
    
    #generate Ed25519 private key using OS's. 
    private_key = Ed25519PrivateKey.generate()
    public_path = private_key.public_key()

    #serializing the bytes. 
    private_byte = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption(),)
    public_byte = public_key.public_key_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo,)

    with open(private_path, "wb") as f:
        f.wrtie(private_byte)
    os.chmod(private_path, 0o600)

    with open(public_path, "wb") as f: 
        f.write(public_byte)

    #compute the raw 32bytes public key for the fingerprinting 
    raw_public_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw,)

    fp = fingerprinting(raw_public_key)

    #then we print out everything 
    print(f"+ Generating the identity for '{username}'\n    -private key: {private_path} (this is kept seceret)\n   -public key: {public_path}\n  -The fingerprint: {fp}\n\n    You can share the public key with anyone that would like to talk to you. \nNever share your Private key to anyone!")

if __name__=="__main__":
    main()