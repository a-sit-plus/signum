package at.asitplus.signum.indispensable.agree

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Decodable
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.sign.ECDSAPrivateKey
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import kotlin.jvm.JvmName

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
interface KeyAgreementPublicValue : Asn1Encodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value as an [ECDSAPublicKey]
         */
        fun asCryptoPublicKey(): ECDSAPublicKey
    }
    companion object : Asn1Decodable<Asn1Sequence, ECDH> {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
    }
}

suspend fun KeyAgreementPublicValue.keyAgreement(privateValue: KeyAgreementPrivateValue) =
    privateValue.keyAgreement(this)

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
@JvmName("keyAgreementECDH")
suspend fun KeyAgreementPublicValue.ECDH.keyAgreement(privateValue: ECDSAPrivateKey) =
    privateValue.keyAgreement(this)
