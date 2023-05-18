const ecrypt = require('jsecrypt')

let aliceKeyPair = new ecrypt.KeyPair()
let bobKeyPair = new ecrypt.KeyPair()

let bobPublicKey = bobKeyPair.public()

console.log(bobPublicKey.toJSON().data)

let aliceSecureMessage = new ecrypt.SecureMessage(aliceKeyPair.private(),
                                                  bobPublicKey)
let message = Buffer.from('a message')

let encryptedMessage = aliceSecureMessage.encrypt(message)

//console.log(encryptedMessage.toJSON().data)

let bobSecureMessage = new ecrypt.SecureMessage(bobKeyPair.private(),
                                                aliceKeyPair.public())

let decryptedMessage = bobSecureMessage.decrypt(encryptedMessage)

console.log(decryptedMessage.toString())


