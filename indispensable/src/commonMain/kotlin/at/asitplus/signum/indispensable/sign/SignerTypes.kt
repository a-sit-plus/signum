package at.asitplus.signum.indispensable.sign

import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.agree.UsableECDHPrivateValue

/** A [Signer] that signs using ECDSA. */
interface ECDSASigner : Signer, UsableECDHPrivateValue {
    override val signatureAlgorithm: ECDSAAlgorithm
    override val publicKey: ECDSAPublicKey

    override val publicValue: KeyAgreementPublicValue.ECDH get() = publicKey
}

/**
 * A [Signer] that signs using RSA.
 *
 * On iOS, RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length,
 * and trailer field `1`. Other RSA-PSS parameter combinations fail as unsupported by the platform.
 */
interface RSASigner : Signer {
    override val signatureAlgorithm: RSAAlgorithm
    override val publicKey: RSAPublicKey
}

interface ExportableECDSASigner : Signer.WithExportableKey, ECDSASigner {
    @SecretExposure
    override suspend fun exportPrivateKey(): ECDSAPrivateKey.WithPublicKey
}

interface ExportableRSASigner : Signer.WithExportableKey, RSASigner {
    @SecretExposure
    override suspend fun exportPrivateKey(): RSAPrivateKey
}

fun ECDSAAlgorithm.signerFor(
    privateKey: ECDSAPrivateKey.WithPublicKey,
    configure: DSLConfigureFn<InMemorySignerConfiguration> = null)
        = (this as SignatureAlgorithm).signerFor(privateKey, configure) as ECDSASigner

val ECDSASigner.curve get() = publicKey.curve

/**
 * Creates an RSA signer for [privateKey].
 *
 * On iOS, RSA-PSS supports only MGF1 using the signature digest, a salt length equal to the digest output length,
 * and trailer field `1`.
 */
fun RSAAlgorithm.signerFor(privateKey: RSAPrivateKey) =
    (this as SignatureAlgorithm).signerFor(privateKey) as RSASigner
