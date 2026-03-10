package at.asitplus.signum.supreme.sign

import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.EcdsaSignatureAlgorithm
import at.asitplus.signum.indispensable.RsaSignatureAlgorithm
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.toJcaPrivateKey


actual fun makePrivateKeySigner(
    key: PrivateKey.RSA,
    algorithm: RsaSignatureAlgorithm
): Signer.RSA = AndroidEphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: PrivateKey.EC.WithPublicKey,
    algorithm: EcdsaSignatureAlgorithm
): Signer.ECDSA = AndroidEphemeralSigner.EC(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)
