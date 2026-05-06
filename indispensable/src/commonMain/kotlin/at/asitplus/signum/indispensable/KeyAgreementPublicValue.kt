package at.asitplus.signum.indispensable

import at.asitplus.awesn1.WithPemLabel
import at.asitplus.awesn1.PemLabelSpec


/**
 * Key agreement public value. Must be PEM encodable/decodable.
 */
sealed interface KeyAgreementPublicValue : WithPemLabel {

    override val pemLabel: String get() = canonicalPemLabel

    /**
     * ECDH key agreement public value. Is always an EC public key, thus comes with [asCryptoPublicKey]
     */
    interface ECDH : KeyAgreementPublicValue {
        /**
         * Returns this value as a [CryptoPublicKey.EC]
         */
        fun asCryptoPublicKey(): CryptoPublicKey.EC
    }

    companion object : PemLabelSpec<ECDH> {

        override val canonicalPemLabel: String
            get() = "PUBLIC KEY"
    }
}
