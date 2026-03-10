package at.asitplus.signum.supreme.sign

import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.EcdsaSignatureAlgorithm
import at.asitplus.signum.indispensable.PrivateKey
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.RsaSignatureAlgorithm
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.toJcaPrivateKey
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn


actual fun makePrivateKeySigner(
    key: PrivateKey.RSA,
    algorithm: RsaSignatureAlgorithm
): Signer.RSA = EphemeralSigner.RSA(
    config = EphemeralSignerConfiguration(),
    privateKey = key.toJcaPrivateKey().getOrThrow(),
    publicKey = key.publicKey,
    signatureAlgorithm = algorithm
)

actual fun makePrivateKeySigner(
    key: PrivateKey.EC.WithPublicKey,
    algorithm: EcdsaSignatureAlgorithm
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
    privateKey: PrivateKey.WithPublicKey<*>,
    configure: DSLConfigureFn<JvmEphemeralSignerCompatibleConfiguration>
) = catching {
    when (this) {
        is SignatureAlgorithm.ECDSA -> {
            require(privateKey is PrivateKey.EC) {
                "Algorithm and Key mismatch: ${this::class.simpleName} + ${privateKey::class.simpleName}"
            }
            EphemeralSigner.EC(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey().getOrThrow(),
            publicKey = privateKey.publicKey as PublicKey.EC,
            signatureAlgorithm = this
        )
        }

        is SignatureAlgorithm.RSA -> {
            require(privateKey is PrivateKey.RSA) {
                "Algorithm and Key mismatch: ${this::class.simpleName} + ${privateKey::class.simpleName}"
            }
            EphemeralSigner.RSA(
            config = DSL.resolve(
                ::EphemeralSignerConfiguration,
                configure
            ),
            privateKey = privateKey.toJcaPrivateKey().getOrThrow(),
            publicKey = privateKey.publicKey as PublicKey.RSA,
            signatureAlgorithm = this
        )
        }

        else -> throw UnsupportedCryptoException("Unsupported signature algorithm $this")
    }
}
