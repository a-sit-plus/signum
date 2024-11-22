package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.*


actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA = EphemeralSigner.RSA(config = EphemeralSignerConfiguration(), privateKey = key.toJcaPrivateKey().getOrThrow(), publicKey = key.publicKey, signatureAlgorithm = algorithm)

actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA = EphemeralSigner.EC(config = EphemeralSignerConfiguration(), privateKey = key.toJcaPrivateKey().getOrThrow(), publicKey = key.publicKey!!, signatureAlgorithm = algorithm)

