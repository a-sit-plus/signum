package at.asitplus.signum.supreme.agreement

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.internals.corecall
import at.asitplus.signum.internals.takeFromCF
import at.asitplus.signum.internals.toByteArray
import at.asitplus.signum.supreme.dsl.DSL
import at.asitplus.signum.supreme.os.IosSigner
import at.asitplus.signum.supreme.os.IosSignerSigningConfiguration
import at.asitplus.signum.supreme.sign.ECPrivateKeySigner
import at.asitplus.signum.supreme.sign.EphemeralSigner
import at.asitplus.signum.supreme.sign.PrivateKeySigner
import at.asitplus.signum.supreme.sign.Signer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.memScoped
import platform.Foundation.NSData

@OptIn(ExperimentalForeignApi::class)
internal actual fun Signer.ECDSA.performAgreement(publicKey: CryptoPublicKey.EC): ByteArray {

    return catchingUnwrapped {

        val priv =  if( this is EphemeralSigner.EC)
            this.privateKey.value
        else if (this is IosSigner)
            this.privateKeyManager.get(DSL.resolve(::IosSignerSigningConfiguration, null)).value
        else if(this is ECPrivateKeySigner)
            this.secKey
        else throw IllegalArgumentException(this::class.qualifiedName!!)
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
}
