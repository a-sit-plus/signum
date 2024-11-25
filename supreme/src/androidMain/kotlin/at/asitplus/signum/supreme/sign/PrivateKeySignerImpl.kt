package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.*
import kotlin.UnsupportedOperationException


actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA,
    destroySource: Boolean
): Signer.RSA = AndroidEphemeralSigner.RSA(config = EphemeralSignerConfiguration(), privateKey = key.toJcaPrivateKey(destroySource).getOrThrow(), publicKey = key.publicKey, signatureAlgorithm = algorithm)

actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC,
    algorithm: SignatureAlgorithm.ECDSA,
    destroySource: Boolean
): Signer.ECDSA = AndroidEphemeralSigner.EC(config = EphemeralSignerConfiguration(), privateKey = key.toJcaPrivateKey(destroySource).getOrThrow(), publicKey = key.publicKey!!, signatureAlgorithm = algorithm)
