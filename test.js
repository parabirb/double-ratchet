// taken from alax's forward-secrecy
// im feeling lazy rn
var tweetnacl = require("tweetnacl");
var SecretSession = require(".");

var aliceIk = tweetnacl.box.keyPair();
var aliceHk = tweetnacl.box.keyPair();
var bobIk = tweetnacl.box.keyPair();
var bobHk = tweetnacl.box.keyPair();

var aliceSession = new SecretSession();

aliceSession
    .identity(aliceIk)
    .handshake(aliceHk)
    .theirIdentity(bobIk.publicKey)
    .theirHandshake(bobHk.publicKey)
    .setRole('initiator')
    .computeMasterKey()
    .then(function () { console.log('ready!'); })

var bobSession = new SecretSession();

bobSession
    .identity(bobIk)
    .handshake(bobHk)
    .theirIdentity(aliceIk.publicKey)
    .theirHandshake(aliceHk.publicKey)
    .setRole('receiver')
    .computeMasterKey()
    .then(function () { console.log('ready!'); })

bobSession.encrypt('Hello Alice!').then(function (encryptedMessage) {
    console.log(encryptedMessage);
    aliceSession.decrypt(encryptedMessage).then(function (result) {
        console.log(result.cleartext);
    })
})

aliceSession.encrypt('Hello Bob!').then(function (encryptedMessage) {
    console.log(encryptedMessage);
    bobSession.decrypt(encryptedMessage).then(function (result) {
        console.log(result.cleartext);
    })
})