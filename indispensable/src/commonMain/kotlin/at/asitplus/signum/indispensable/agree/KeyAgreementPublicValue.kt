package at.asitplus.signum.indispensable.agree

import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.DerPemDecodable
import at.asitplus.signum.indispensable.DerPemEncodable
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import kotlin.jvm.JvmName

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
interface KeyAgreementPublicValue : DerPemEncodable<SubjectPublicKeyInfo> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value as an [EcdsaPublicKey]
         */
        fun asCryptoPublicKey(): EcdsaPublicKey
    }
    companion object : DerPemDecodable<SubjectPublicKeyInfo, KeyAgreementPublicValue> {
        override fun decodeFromTlv(element: SubjectPublicKeyInfo, der: Der) =
            CryptoPublicKey.decodeFromTlv(element, der) as KeyAgreementPublicValue

        override val canonicalPemLabel: String
            get() = CryptoPublicKey.canonicalPemLabel
    }
}

suspend fun KeyAgreementPublicValue.keyAgreement(privateValue: KeyAgreementPrivateValue) =
    privateValue.keyAgreement(this)

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
@JvmName("keyAgreementECDH")
suspend fun KeyAgreementPublicValue.ECDH.keyAgreement(privateValue: EcdsaPrivateKey) =
    privateValue.keyAgreement(this)
