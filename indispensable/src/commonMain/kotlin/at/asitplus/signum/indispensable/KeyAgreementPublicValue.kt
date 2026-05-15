package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Encodable
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Decodable

/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
sealed interface KeyAgreementPublicValue : Asn1Encodable<Asn1Sequence> {
    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH: KeyAgreementPublicValue {
        /**
         * Returns this value ad a [CryptoPublicKey.EC]
         */
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }
    companion object : Asn1Decodable<Asn1Sequence, ECDH> {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
    }
}
