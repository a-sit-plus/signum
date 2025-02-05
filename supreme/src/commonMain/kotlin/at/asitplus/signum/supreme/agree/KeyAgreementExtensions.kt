package at.asitplus.signum.supreme.agree

import at.asitplus.KmmResult
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.signerFor
import kotlin.jvm.JvmName

interface UsableECDHPrivateValue : KeyAgreementPrivateValue.ECDH {
    suspend fun keyAgreement(publicValue: KeyAgreementPublicValue.ECDH): KmmResult<ByteArray>
}

suspend fun KeyAgreementPrivateValue.keyAgreement(publicValue: KeyAgreementPublicValue): KmmResult<ByteArray> {
    if (publicValue !is KeyAgreementPublicValue.ECDH)
        return KmmResult.failure(IllegalArgumentException("Expected KeyAgreementPublicValue.ECDH, got ${publicValue::class.simpleName}"))
    return when (this) {
        is UsableECDHPrivateValue -> this.keyAgreement(publicValue)
        is CryptoPrivateKey.EC.WithPublicKey -> SignatureAlgorithm.ECDSAwithSHA256.signerFor(this)
            .transform { it.keyAgreement(publicValue) }

        else -> KmmResult.failure(IllegalStateException("Type hierarchy failure? Actual type is ${this::class.qualifiedName ?: "<null>"}"))
    }
}

@JvmName("keyAgreementEC")
suspend fun CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>.keyAgreement(publicValue: KeyAgreementPublicValue) =
    (this as KeyAgreementPrivateValue.ECDH).keyAgreement(publicValue)

suspend fun KeyAgreementPublicValue.keyAgreement(privateValue: KeyAgreementPrivateValue) =
    privateValue.keyAgreement(this)

@Suppress("INVISIBLE_MEMBER", "INVISIBLE_REFERENCE")
@kotlin.internal.LowPriorityInOverloadResolution
@JvmName("keyAgreementECDH")
suspend fun KeyAgreementPublicValue.ECDH.keyAgreement(privateValue: CryptoPrivateKey.WithPublicKey<CryptoPublicKey.EC>) =
    privateValue.keyAgreement(this)

fun KeyAgreementPrivateValue.ECDH.Companion.Ephemeral(curve: ECCurve = ECCurve.SECP_256_R_1)
        : KmmResult<KeyAgreementPrivateValue.ECDH> =
    Signer.Ephemeral {
        ec { this.curve = curve }
    }.map { it as Signer.ECDSA }
