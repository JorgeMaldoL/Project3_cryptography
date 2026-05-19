# Project3_cryptography

Simple encrypted chat demo. Tools:
- `keygen.py` — make an Ed25519 identity for a user
- `client.py` — chat client that talks to the relay
- `relay_server.py` — simple relay and key directory (untrusted)

## Trust model

Identity is a long-term Ed25519 key pair you make with `keygen.py`.
The relay will hand out public keys, but the relay is NOT trusted.
Anyone can upload any key and claim any name — the relay just stores blobs.

Client-side TOFU handles trust:

- First time you see someone, run `/secure <user>`.
	- client fetches their public key from the relay and shows the fingerprint.
	- if you accept, it stores the fingerprint with `verified=false` in `~/.encchat/known_peers.json`.
- Next time you talk to them, the client accepts silently if the fingerprint matches.
- If the fingerprint changed, the client prints a loud warning and refuses to proceed.

Run `/verify <user>` after you compare fingerprints out-of-band (phone, in-person).
That flips `verified` to true and closes the obvious first-session MITM hole in TOFU.

Keep it simple: relay helps distribute keys, clients decide whether to trust them.
