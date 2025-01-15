package at.asitplus.signum.supreme.agreement

import android.security.keystore.UserNotAuthenticatedException
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.HazardousMaterials
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.dsl.DSLConfigureFn
import at.asitplus.signum.supreme.hazmat.jcaPrivateKey
import at.asitplus.signum.supreme.os.AndroidKeystoreSigner
import at.asitplus.signum.supreme.os.AndroidSignerSigningConfiguration
import at.asitplus.signum.supreme.os.PlatformSigningProviderSignerSigningConfigurationBase
import at.asitplus.signum.supreme.sign.Signer

actual suspend fun Signer.ECDSA.performAgreement(
    publicKey: CryptoPublicKey.EC,
    config: DSLConfigureFn<PlatformSigningProviderSignerSigningConfigurationBase>
): ByteArray = if (this is AndroidKeystoreSigner) {
    //HW-backed
    val resolvedConfig = DSL.resolve(::AndroidSignerSigningConfiguration, config)
    val agreement = javax.crypto.KeyAgreement.getInstance("ECDH", "AndroidKeyStore").also {
        //Android bug here: impossible to do for auth-on-every use keys. Earliest possible fix: Android 16, if ever
        try {
            it.init(jcaPrivateKey)
        } catch (_: UserNotAuthenticatedException) {
            attemptBiometry(
                DSL.ConfigStack(
                    resolvedConfig.unlockPrompt.v,
                    this.config.unlockPrompt.v
                ),
                null
            )
            it.init(jcaPrivateKey)
        }
    }
    agreement.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
    agreement.generateSecret()
} else {
    //any other signer (Ephemeral, Private-key based)
    javax.crypto.KeyAgreement.getInstance("ECDH").also {
        @OptIn(HazardousMaterials::class)
        it.init(jcaPrivateKey)
        it.doPhase(publicKey.toJcaPublicKey().getOrThrow(), true)
    }.generateSecret()
}
