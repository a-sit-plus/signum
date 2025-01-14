package at.asitplus.signum.supreme.agreement

import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricPrompt.CryptoObject
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.os.AndroidKeyStoreProvider
import at.asitplus.signum.supreme.os.AndroidKeystoreSigner
import at.asitplus.signum.supreme.os.AndroidSignerSigningConfiguration
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.os.needsAuthenticationForEveryUse
import at.asitplus.signum.supreme.sign.Signer

actual suspend fun Signer.ECDSA.performAgreement(
    publicKey: CryptoPublicKey.EC,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase>
): ByteArray {
    /*TODO: check auth similar to https://github.com/a-sit-plus/kmp-crypto/blob/02ee22227dcef3ee03e65a19f0aa578168f7b518/supreme/src/androidMain/kotlin/at/asitplus/signum/supreme/os/AndroidKeyStoreProvider.kt#L360*/

    return if (this is AndroidKeystoreSigner) {
        val resolvedConfig = DSL.resolve(::AndroidSignerSigningConfiguration, config)
        javax.crypto.KeyAgreement.getInstance("ECDH", "AndroidKeyStore").also {

            if (needsAuthenticationForEveryUse) {
                it.init(jcaPrivateKey)
                attemptBiometry(
                    DSL.ConfigStack(resolvedConfig.unlockPrompt.v, resolvedConfig.unlockPrompt.v),
                    null //TODO ????
                )
            } else {
                try {
                    it.init(jcaPrivateKey)
                } catch (_: UserNotAuthenticatedException) {
                    attemptBiometry(
                        DSL.ConfigStack(
                            resolvedConfig.unlockPrompt.v,
                            resolvedConfig.unlockPrompt.v
                        ),
                        null
                    )
                    it.init(jcaPrivateKey)
                }
            }
            it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
        }.generateSecret()

    } else {
        javax.crypto.KeyAgreement.getInstance("ECDH", "AndroidKeyStore").also {
            @OptIn(HazardousMaterials::class)
            it.init(jcaPrivateKey)
            it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
        }.generateSecret()
    }
}