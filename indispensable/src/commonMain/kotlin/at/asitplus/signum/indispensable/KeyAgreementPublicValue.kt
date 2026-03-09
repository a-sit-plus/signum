package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.LabelPemDecodable

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
sealed interface KeyAgreementPublicValue : Asn1PemEncodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value ad a [CryptoPublicKey.EC]
         */
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }
    companion object : LabelPemDecodable<Asn1Sequence, ECDH>("PUBLIC KEY") {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
    }
}
