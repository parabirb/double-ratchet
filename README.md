# double-ratchet
double-ratchet is a library for signal's [double ratchet (revision 1)](https://signal.org/docs/specifications/doubleratchet) in JS. its API mimics that of [forward-secrecy](https://github.com/alax/forward-secrecy), although the cryptographic primitives are different. **tweetnacl, tweetnacl-auth-js, and tweetnacl-util-js are required.** some functions like session loading and exporting have been removed as they are not used in wrongthink.

## cryptographic primitives
* XSalsa20-Poly1305 for encryption/decryption
* X25519 for Diffie-Hellman key exchange
* HMAC-SHA-512 as a KDF

## security
if i fucked this up somehow i will be extremely disappointed in myself

this library is NOT misuse-proof. if you manage to screw something up that is on you.

## api documentation
there is no documentation for the API. please refer to forward-secrecy's documentation if you want to use this.
