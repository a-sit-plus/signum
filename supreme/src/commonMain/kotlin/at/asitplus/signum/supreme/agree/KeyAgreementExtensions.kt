package at.asitplus.signum.supreme.agree

import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.agree.KeyAgreementPrivateValue

/**
 * Generates an ephemeral ECDH private value on the provided [curve].
 */
suspend fun KeyAgreementPrivateValue.ECDH.Companion.Ephemeral(curve: ECCurve = ECCurve.SECP_256_R_1)
        : KeyAgreementPrivateValue.ECDH =
    Signer.Ephemeral {
        ec { this.curve = curve }
    } as Signer.ECDSA
