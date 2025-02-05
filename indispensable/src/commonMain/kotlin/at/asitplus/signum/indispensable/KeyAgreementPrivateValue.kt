package at.asitplus.signum.indispensable

import at.asitplus.KmmResult

sealed interface KeyAgreementPrivateValue {
    val publicValue: KeyAgreementPublicValue

    interface ECDH: KeyAgreementPrivateValue {
        override val publicValue: KeyAgreementPublicValue.ECDH
        companion object
    }
}
