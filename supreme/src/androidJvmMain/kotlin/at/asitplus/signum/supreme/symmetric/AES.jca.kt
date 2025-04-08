package at.asitplus.signum.supreme.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.jcaKeySpec
import at.asitplus.signum.indispensable.jcaName
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.isAuthenticated
import at.asitplus.signum.indispensable.symmetric.isIntegrated
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@OptIn(HazardousMaterials::class)
internal object AESJCA {
    fun initCipher(
        mode: PlatformCipher.Mode,
        algorithm: SymmetricEncryptionAlgorithm.AES<*, *, *>,
        key: ByteArray,
        nonce: ByteArray?,
        aad: ByteArray?
    ) = Cipher.getInstance(algorithm.jcaName).apply {
        if (algorithm.isAuthenticated() && algorithm.isIntegrated())
            init(
                mode.jcaCipherMode,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                GCMParameterSpec(algorithm.authTagSize.bits.toInt(), nonce)
            )
        else if (algorithm is SymmetricEncryptionAlgorithm.AES.CBC<*, *>) //covers unauthenticated and CBC-HMAC, because CBC will always delegate to here
            init(
                mode.jcaCipherMode,
                SecretKeySpec(key, algorithm.jcaKeySpec),
                IvParameterSpec(nonce)
            )
        else if ((algorithm is SymmetricEncryptionAlgorithm.AES.ECB) || algorithm is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394) {
            init(
                mode.jcaCipherMode,
                SecretKeySpec(key, algorithm.jcaKeySpec),
            )
        } else TODO("Algorithm $algorithm is unsupported ")
        aad?.let { if (algorithm is SymmetricEncryptionAlgorithm.AES.GCM) updateAAD(it) /*CBC-HMAC we do ourselves*/ }
    }
}
