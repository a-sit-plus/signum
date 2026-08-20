package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.JvmEphemeralSignerCompatibleConfiguration
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAAlgorithm
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAAlgorithm
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


actual fun makePrivateKeySigner(
    key: RSAPrivateKey,
    algorithm: RSAAlgorithm
): Signer.RSA = EphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: ECDSAPrivateKey.WithPublicKey,
    algorithm: ECDSAAlgorithm
): Signer.ECDSA = EphemeralSigner.EC(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

/**
 * Creates a signer for the specified [privateKey]. Fails if the key type does not match the signature algorithm type (EC/RSA) or if it has no public key attached
 * This JVM-specific variant allows for optionally specifying a provider
 *
 * @see at.asitplus.signum.dsl.JvmEphemeralSignerCompatibleConfiguration
 *
 */
fun SignatureAlgorithm.signerFor(
    privateKey: CryptoPrivateKey.WithPublicKey<*>,
    configure: DSLConfigureFn<JvmEphemeralSignerCompatibleConfiguration>
): Signer {
    require(
        (this is ECDSAAlgorithm && privateKey is ECDSAPrivateKey) ||
                (this is RSAAlgorithm && privateKey is RSAPrivateKey)
    ) { "Algorithm and Key mismatch: ${this::class.simpleName} + ${privateKey::class.simpleName}" }

    return when (this) {
        is ECDSAAlgorithm -> EphemeralSigner.EC(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey(),
            publicKey = privateKey.publicKey as ECDSAPublicKey,
            signatureAlgorithm = this
        )

        is RSAAlgorithm -> EphemeralSigner.RSA(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey(),
            publicKey = privateKey.publicKey as RSAPublicKey,
            signatureAlgorithm = this
        )
        else -> TODO("providerize")
    }
}