package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.PemDecodable
import at.asitplus.signum.indispensable.asn1.PemEncodable

sealed interface KeyAgreementPublicValue : PemEncodable<Asn1Sequence> {
    interface ECDH: KeyAgreementPublicValue {
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }
    companion object : PemDecodable<Asn1Sequence, ECDH>("PUBLIC KEY") {
        override fun doDecode(src: Asn1Sequence) = CryptoPublicKey.doDecode(src) as CryptoPublicKey.EC
    }
}
