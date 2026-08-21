package at.asitplus.signum.supreme.os

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.dsl.PlatformSignerConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningKeyConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningProviderConfigurationBase
import at.asitplus.signum.dsl.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.dsl.SignerConfiguration
import at.asitplus.signum.indispensable.Attestation
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.supreme.SignatureResult
import at.asitplus.signum.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.dsl.SigningKeyConfiguration
import at.asitplus.signum.dsl.purposes

internal inline val SigningKeyConfiguration.AlgorithmSpecific.allowsSigning get() =
    when (this) {
        is PlatformSigningKeyConfigurationBase.ECConfiguration -> this.purposes.v.signing
        is PlatformSigningKeyConfigurationBase.RSAConfiguration -> this.purposes.v.signing
        else -> true
    }

internal inline val SigningKeyConfiguration.AlgorithmSpecific.allowsDecrypting get() =
    when (this) {
        is PlatformSigningKeyConfigurationBase.RSAConfiguration -> this.purposes.v.decrypting
        is SigningKeyConfiguration.RSAConfiguration -> true
        else -> false
    }

internal inline val SigningKeyConfiguration.AlgorithmSpecific.allowsKeyAgreement get() =
    when (this) {
        is PlatformSigningKeyConfigurationBase.ECConfiguration -> this.purposes.v.keyAgreement
        is SigningKeyConfiguration.ECConfiguration -> true
        else -> false
    }

interface PlatformSigningProviderSigner
    <SigningConfiguration: PlatformSigningProviderSignerSigningConfigurationBase, AttestationT: Attestation>
    : Signer.WithAlias, Signer.Attestable<AttestationT> {

    suspend fun trySetupUninterruptedSigning(configure: DSLConfigureFn<SigningConfiguration> = null) {}
    override suspend fun trySetupUninterruptedSigning() = trySetupUninterruptedSigning(null)

    suspend fun sign(data: SignatureInput, configure: DSLConfigureFn<SigningConfiguration> = null) : SignatureResult<*>
    suspend fun sign(data: ByteArray, configure: DSLConfigureFn<SigningConfiguration> = null) =
        sign(SignatureInput(data), configure)
    suspend fun sign(data: Sequence<ByteArray>, configure: DSLConfigureFn<SigningConfiguration> = null) =
        sign(SignatureInput(data), configure)
    override suspend fun sign(data: SignatureInput) = sign(data, null)
    override suspend fun sign(data: ByteArray) = sign(SignatureInput(data), null)
    override suspend fun sign(data: Sequence<ByteArray>) = sign(SignatureInput(data), null)

    interface ECDSA
    <SigningConfiguration: PlatformSigningProviderSignerSigningConfigurationBase, AttestationT: Attestation>
        : PlatformSigningProviderSigner<SigningConfiguration, AttestationT>, Signer.ECDSA
    {
        suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH, configure: DSLConfigureFn<SigningConfiguration> = null): KmmResult<ByteArray>
        override suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH) = keyAgreement(publicValue, null)
    }
}

internal expect fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*>

/** KT-71089 workaround
 * @see PlatformSigningProvider */
interface PlatformSigningProviderI<out SignerT: PlatformSigningProviderSigner<*,*>,
        out SignerConfigT: PlatformSignerConfigurationBase,
        out KeyConfigT: PlatformSigningKeyConfigurationBase<*>>
    : SigningProviderI<SignerT, SignerConfigT, KeyConfigT> {

    companion object {
        operator fun invoke(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase> = null) =
            catching { getPlatformSigningProvider(configure) }
    }
}
/**
 * An interface to some underlying persistent storage for private key material. Stored keys are identified by a unique string "alias" for each key.
 * You can [create signing keys][createSigningKey], [get signers for existing keys][getSignerForKey], or [delete signing keys][deleteSigningKey].
 *
 * To obtain a platform signing provider in platform-agnostic code, use `PlatformSigningProvider`.
 * In platform-specific code, it is currently recommended to directly interface with your platform signing provider to get platform-specific functionality.
 * (Platform-specific types for `PlatformSigningProvider` are currently blocked by KT-71036.)
 *
 * Created keys can be configured using the [SigningKeyConfiguration] DSL.
 * Signers can be configured using the [SignerConfiguration] DSL.
 * When creating a key, the returned signer's configuration is embedded in the signing key configuration as `signer {}`.
 *
 * @see JKSProvider
 * @see AndroidKeyStoreProvider
 * @see IosKeychainProvider
 */
val PlatformSigningProvider get() = getPlatformSigningProvider(null)

/** KT-71089 workaround
 * @see SigningProvider */
interface SigningProviderI<out SignerT: Signer.WithAlias,
        out SignerConfigT: SignerConfiguration,
        out KeyConfigT: PlatformSigningKeyConfigurationBase<*>> {
    suspend fun createSigningKey(alias: String, configure: DSLConfigureFn<KeyConfigT> = null): KmmResult<SignerT>
    suspend fun getSignerForKey(alias: String, configure: DSLConfigureFn<SignerConfigT> = null): KmmResult<SignerT>
    suspend fun deleteSigningKey(alias: String): KmmResult<Unit>

    companion object {
        fun Platform(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase> = null) =
            getPlatformSigningProvider(configure)
    }
}

/** @see PlatformSigningProvider */
typealias SigningProvider = SigningProviderI<*,*,*>
