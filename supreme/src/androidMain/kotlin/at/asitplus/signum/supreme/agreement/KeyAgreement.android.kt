package at.asitplus.signum.supreme.agreement

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.os.AndroidKeyStoreProvider
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.sign.Signer

actual fun Signer.ECDSA.performAgreement(publicKey: CryptoPublicKey.EC, config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase>): ByteArray =
    /*TODO: check auth similar to https://github.com/a-sit-plus/kmp-crypto/blob/02ee22227dcef3ee03e65a19f0aa578168f7b518/supreme/src/androidMain/kotlin/at/asitplus/signum/supreme/os/AndroidKeyStoreProvider.kt#L360*/
    javax.crypto.KeyAgreement.getInstance("ECDH","AndroidKeyStore").also {
        @OptIn(HazardousMaterials::class)
        it.init(jcaPrivateKey)
        it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
    }.generateSecret()
