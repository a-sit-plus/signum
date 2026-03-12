package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

@Serializable
data class JwsGeneral(
    @Serializable(ByteArrayBase64UrlSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val payload: ByteArray,
    @Serializable
    @SerialName(SerialNames.SIGNATURES)
    val signatureElements: List<SignatureElement>
) : JWS() {

    init {
        require(signatureElements.isNotEmpty()) { "At least one signature is required" }
    }

    @Transient
    val jwsHeaders: List<JwsHeader> = signatureElements.map { it.jwsHeader }

    fun getSignatureAt(index: Int) = getSignature(jwsHeaders[index].algorithm, signatureElements[index].plainSignature)
    fun getSignatureInputAt(index: Int) = getSignatureInput(signatureElements[index].plainProtectedHeader, payload)

    /**
     * @return New [JwsGeneral] object with appended Signature
     */
    fun appendSignature(jwsFlattened: JwsFlattened): JwsGeneral {
        require(payload.contentEqualsIfArray(jwsFlattened.payload)) {
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

        if (!payload.contentEquals(other.payload)) return false
        if (signatureElements != other.signatureElements) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.contentHashCode()
        result = 31 * result + signatureElements.hashCode()
        return result
    }

    companion object {
        operator fun invoke(jwsFlattened: List<JwsFlattened>): JwsGeneral = jwsFlattened.toJwsGeneral()
    }
}


fun JwsGeneral.toJwsFlattened(): List<JwsFlattened> =
    signatureElements.map {
        JwsFlattened(
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            payload = this.payload,
            plainSignature = it.plainSignature
        )
    }
