package at.asitplus.signum.indispensable.agree

import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.fromAsn1Representation
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import kotlin.jvm.JvmName

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
interface KeyAgreementPublicValue : Encodable {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value as an [EcdsaPublicKey]
         */
        fun asCryptoPublicKey(): EcdsaPublicKey
    }
    companion object : Decodable<KeyAgreementPublicValue> {
        fun fromAsn1Representation(element: SubjectPublicKeyInfo) =
            CryptoPublicKey.fromAsn1Representation(element) as KeyAgreementPublicValue

    }
}

suspend fun KeyAgreementPublicValue.keyAgreement(privateValue: KeyAgreementPrivateValue) =
    privateValue.keyAgreement(this)

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
@JvmName("keyAgreementECDH")
suspend fun KeyAgreementPublicValue.ECDH.keyAgreement(privateValue: EcdsaPrivateKey) =
    privateValue.keyAgreement(this)
