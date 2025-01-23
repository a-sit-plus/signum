package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.symmetric.SignatureAlgorithm
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.RSA,
    algorithm: SignatureAlgorithm.RSA
): Signer.RSA = EphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: CryptoPrivateKey.EC.WithPublicKey,
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
 * @see JvmEphemeralSignerCompatibleConfiguration
 *
 */
fun SignatureAlgorithm.signerFor(
    privateKey: CryptoPrivateKey.WithPublicKey<*>,
    configure: DSLConfigureFn<JvmEphemeralSignerCompatibleConfiguration>
) = catching {
    require(
        (this is SignatureAlgorithm.ECDSA && privateKey is CryptoPrivateKey.EC) ||
                (this is SignatureAlgorithm.RSA && privateKey is CryptoPrivateKey.RSA)
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

        is SignatureAlgorithm.HMAC -> throw UnsupportedOperationException("HMAC is not yet supported!")
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