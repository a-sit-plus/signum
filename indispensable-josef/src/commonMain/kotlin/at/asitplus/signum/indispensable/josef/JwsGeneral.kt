package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlNoPaddingSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * General JSON JWS.
 *
 * A general JWS carries one payload and one or more [signatureElements]. Each [SignatureElement] contains the header
 * fragments for one signature and exposes its merged effective [JwsHeader]. All signatures in a [JwsGeneral] share
 * the same payload.
 *
 * [plainPayload] stores the plain payload bytes. JSON serialization base64url-encodes those bytes for the `payload`
 * member, so callers should not pre-encode them.
 */
@ConsistentCopyVisibility
@Serializable
data class JwsGeneral internal constructor(
    @Serializable(ByteArrayBase64UrlNoPaddingSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val plainPayload: ByteArray,
    @Serializable
    @SerialName(SerialNames.SIGNATURES)
    val signatureElements: List<SignatureElement>
) : JWS() {

    init {
        require(signatureElements.isNotEmpty()) { "At least one signature is required" }
    }

    @Transient
    val jwsHeaders: List<JwsHeader> = signatureElements.map { it.jwsHeader }

    @Transient
    val signatures = signatureElements.map { it.signature }

    @Transient
    val signatureInputs = signatureElements.map { getSignatureInput(it.plainProtectedHeader, plainPayload) }

    /**
     * Returns a new [JwsGeneral] with one additional signature over the same payload.
     */
    fun appendSignature(jwsFlattened: JwsFlattened): JwsGeneral {
        require(plainPayload.contentEqualsIfArray(jwsFlattened.plainPayload)) {
            "Additional signed JWS payload must match existing payload"
        }

        return copy(
            signatureElements = signatureElements + SignatureElement(
                plainSignature = jwsFlattened.plainSignature,
                unprotectedHeader = jwsFlattened.unprotectedHeader,
                plainProtectedHeader = jwsFlattened.plainProtectedHeader,
            )
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsGeneral

        if (!plainPayload.contentEquals(other.plainPayload)) return false
        if (signatureElements != other.signatureElements) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainPayload.contentHashCode()
        result = 31 * result + signatureElements.hashCode()
        return result
    }

    companion object {
        operator fun invoke(jwsFlattened: List<JwsFlattened>): JwsGeneral = jwsFlattened.toJwsGeneral()
    }
}

/**
 * Expands general JSON JWS representation into one flattened JWS per signature.
 */
fun JwsGeneral.toJwsFlattened(): List<JwsFlattened> =
    signatureElements.map {
        JwsFlattened(
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            plainPayload = this.plainPayload,
            plainSignature = it.plainSignature
        )
    }
