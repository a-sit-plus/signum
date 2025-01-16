package at.asitplus.signum.supreme.agreement

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.os.IosSigner
import at.asitplus.signum.supreme.os.IosSignerSigningConfiguration
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.sign.ECPrivateKeySigner
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.toSecKey
import at.asitplus.signum.supreme.sign.Signer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.Foundation.NSData

@OptIn(ExperimentalForeignApi::class, HazardousMaterials::class)
internal actual suspend fun Signer.ECDSA.performAgreement(
    publicKey: CryptoPublicKey.EC,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase>
): ByteArray = catchingUnwrapped {
    val priv = when (this) {
        is EphemeralSigner.EC -> this.privateKey.value
        is IosSigner -> this.privateKeyManager.get(DSL.resolve(::IosSignerSigningConfiguration, config)).value
        is ECPrivateKeySigner -> this.secKey
        else -> throw IllegalArgumentException(this::class.qualifiedName!!)
    }
    memScoped {
        val pub = toSecKey(publicKey)
        return corecall {
            platform.Security.SecKeyCopyKeyExchangeResult(
                priv,
                platform.Security.kSecKeyAlgorithmECDHKeyExchangeStandard,
                pub,
                parameters = null,
                error
            )
        }.let { it.takeFromCF<NSData>() }.toByteArray()
    }
}.getOrThrow()

