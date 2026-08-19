package at.asitplus.signum.supreme.sign

import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.toJcaPrivateKey


actual fun makePrivateKeySigner(
    key: RSAPrivateKey,
    algorithm: RSAAlgorithm
): Signer.RSA = AndroidEphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: ECDSAPrivateKey.WithPublicKey,
    algorithm: ECDSAAlgorithm
): Signer.ECDSA = AndroidEphemeralSigner.EC(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)