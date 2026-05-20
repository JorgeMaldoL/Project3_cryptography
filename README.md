# Project3_cryptography

encrypted chat thing i made for class. pretty simple setup

## files

- `keygen.py` - makes your identity (ed25519 key pair)
- `client.py` - the actual chat client
- `relay_server.py` - middle man server, just passes messages and stores public keys

## how trust works

the relay is NOT trusted, it literally just stores whatever keys people upload so anyone could upload a fake key under your name. thats why the client handles trust itself

first time you wanna talk to someone securely run `/secure <user>`. it pulls their key from the relay and shows u the fingerprint. if u accept it saves it locally with verified=false

next time you message them it checks if the fingerprint still matches. if it changed it freaks out and stops which is the right behavior bc that could be a mitm attack

run `/verify <user>` after you compare fingerprints in person or over the phone or whatever. that flips verified to true and closes the first-session mitm hole that tofu has

basically relay = key distribution, client = decides who to trust
