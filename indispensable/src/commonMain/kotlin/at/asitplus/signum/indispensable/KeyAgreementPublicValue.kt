package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.PemDecodable
import at.asitplus.signum.indispensable.asn1.PemEncodable
import at.asitplus.signum.indispensable.asn1.serialization.Asn1Serializer
import kotlinx.serialization.Serializable

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
@Serializable(with = KeyAgreementPublicValue.Companion::class)
sealed interface KeyAgreementPublicValue : PemEncodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    @Serializable(with = KeyAgreementPublicValue.Companion::class)
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value ad a [CryptoPublicKey.EC]
         */
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }
    companion object : PemDecodable<Asn1Sequence, ECDH>("PUBLIC KEY"), Asn1Serializer<Asn1Sequence,ECDH> {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
    }
}
