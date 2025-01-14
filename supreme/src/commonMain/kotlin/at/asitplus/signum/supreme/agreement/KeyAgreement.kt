package at.asitplus.signum.supreme.agreement

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.curve
import at.asitplus.signum.supreme.sign.signerFor

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 *
 * [config] can be used to display a custom authentication prompt
 */
suspend fun Signer.ECDSA.keyAgreement(
    publicKey: CryptoPublicKey.EC,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase> = null
): KmmResult<ByteArray> = catching {
    require(curve == publicKey.curve) { "Private and public key curve mismatch" }
    performAgreement(publicKey, config)
}

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 *
 * [config] can be used to display a custom authentication prompt
 */
suspend fun CryptoPublicKey.EC.keyAgreement(
    signer: Signer.ECDSA,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase> = null
) = signer.keyAgreement(this, config)


/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
suspend fun CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>.keyAgreement(publicKey: CryptoPublicKey.EC) =
    (SignatureAlgorithm.ECDSA(this.publicKey.curve.nativeDigest, this.publicKey.curve)
        .signerFor(this)
        .getOrThrow() as Signer.ECDSA).keyAgreement(
        publicKey
    )

/**
 * Elliptic-curve Diffie-Hellman key agreement.
 * Curves of public key and signer need to match!
 */
suspend fun CryptoPublicKey.EC.keyAgreement(privateKey: CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>) =
    privateKey.keyAgreement(this)


internal expect suspend fun Signer.ECDSA.performAgreement(
    publicKey: CryptoPublicKey.EC,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase>
): ByteArray