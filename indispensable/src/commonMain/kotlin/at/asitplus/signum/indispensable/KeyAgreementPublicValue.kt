package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable
import at.asitplus.signum.indispensable.key.PublicKey

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
sealed interface KeyAgreementPublicValue : Asn1PemEncodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key.
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value as a [PublicKey.EC]
         */
        fun asPublicKey(): PublicKey.EC

        /**
         * Returns this value as a [PublicKey.EC]
         */
        @Deprecated(
            "Renamed to asPublicKey().",
            ReplaceWith("asPublicKey()")
        )
        fun asCryptoPublicKey(): PublicKey.EC = asPublicKey()
    }
    companion object : LabelPemDecodable<Asn1Sequence, ECDH>("PUBLIC KEY") {
        override fun doDecode(src: Asn1Sequence) = PublicKey.doDecode(src) as PublicKey.EC
    }
}
