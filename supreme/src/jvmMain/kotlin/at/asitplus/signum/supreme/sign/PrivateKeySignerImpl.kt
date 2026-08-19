package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.JvmEphemeralSignerCompatibleConfiguration
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.sign.EC
import at.asitplus.signum.indispensable.sign.RSAPrivateKey
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


actual fun makePrivateKeySigner(
    key: RSAPrivateKey,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA = EphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: EC.WithPublicKey,
    algorithm: SignatureAlgorithm.ECDSA
): Signer.ECDSA = EphemeralSigner.EC(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
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
) = catching {
    require(
        (this is SignatureAlgorithm.ECDSA && privateKey is EC) ||
                (this is SignatureAlgorithm.RSA && privateKey is RSAPrivateKey)
    ) { "Algorithm and Key mismatch: ${this::class.simpleName} + ${privateKey::class.simpleName}" }

    when (this) {
        is SignatureAlgorithm.ECDSA -> EphemeralSigner.EC(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey().getOrThrow(),
            publicKey = privateKey.publicKey as CryptoPublicKey.EC,
            signatureAlgorithm = this
        )

        is SignatureAlgorithm.RSA -> EphemeralSigner.RSA(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey().getOrThrow(),
            publicKey = privateKey.publicKey as CryptoPublicKey.RSA,
            signatureAlgorithm = this
        )
    }
}