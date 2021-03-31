// some somewhat comprehensive tests
const nacl = require("tweetnacl");
const secretSession = require(".");

const aliceIk = nacl.box.keyPair();
const aliceHk = nacl.box.keyPair();
const bobIk = nacl.box.keyPair();
const bobHk = nacl.box.keyPair();

(async () => {
    const aliceSession = new secretSession();

    await aliceSession
        .identity(aliceIk)
        .handshake(aliceHk)
        .theirIdentity(bobIk.publicKey)
        .theirHandshake(bobHk.publicKey)
        .setRole("initiator")
        .computeMasterKey()

    console.log("Alice is ready!");

    const bobSession = new secretSession();

    await bobSession
        .identity(bobIk)
        .handshake(bobHk)
        .theirIdentity(aliceIk.publicKey)
        .theirHandshake(aliceHk.publicKey)
        .setRole("receiver")
        .computeMasterKey()

    console.log("Bob is ready!");

    console.log((await bobSession.decrypt(await aliceSession.encrypt("Alice to Bob (1)"))).cleartext);

    let encrypted = await aliceSession.encrypt("Alice to Bob (out-of-order, 2)");

    console.log((await bobSession.decrypt(await aliceSession.encrypt("Alice to Bob (3)"))).cleartext);
    console.log((await bobSession.decrypt(encrypted)).cleartext);

    console.log((await aliceSession.decrypt(await bobSession.encrypt("Bob to Alice (1)"))).cleartext);

    encrypted = await bobSession.encrypt("Bob to Alice (out-of-order, 2)");

    console.log((await aliceSession.decrypt(await bobSession.encrypt("Bob to Alice (3)"))).cleartext);
    console.log((await aliceSession.decrypt(encrypted)).cleartext);
})();