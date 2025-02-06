package at.asitplus.signum.indispensable

/**
 * Key agreement private value. Always comes with the matching [publicValue].
 */
sealed interface KeyAgreementPrivateValue {
    val publicValue: KeyAgreementPublicValue

    interface ECDH: KeyAgreementPrivateValue {
        override val publicValue: KeyAgreementPublicValue.ECDH
        companion object
    }
}
