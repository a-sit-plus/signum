package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class JwsGeneral(
    @Serializable(ByteArrayBase64UrlSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val payload: ByteArray,
    @Serializable
    @SerialName(SerialNames.SIGNATURES)
    val signatures: List<SignatureElement>
) : JWS() {

    fun getHeaderAt(index: Int): JwsHeader = with(signatures[index]) {
        JwsHeader.fromParts(plainProtectedHeader, unprotectedHeader)
    }
    fun getSignatureAt(index: Int) = getSignature(getHeaderAt(index).algorithm, signatures[index].plainSignature)
    fun getSignatureInputAt(index: Int) = getSignatureInput(signatures[index].plainProtectedHeader, payload)
    /**
     * @return New [JwsGeneral] object with appended Signature
     */
    fun appendSignature(jwsFlattened: JwsFlattened): JwsGeneral {
        require(payload.contentEqualsIfArray(jwsFlattened.payload)) {
            "Additional signed JWS payload must match existing payload"
        }

        return copy(
            signatures = signatures + SignatureElement(
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
        if (signatures != other.signatures) return false

        return true
    }

    override fun hashCode(): Int {
        var result = payload.contentHashCode()
        result = 31 * result + signatures.hashCode()
        return result
    }

    companion object {
        operator fun invoke(jwsFlattened: List<JwsFlattened>): JwsGeneral = jwsFlattened.toJwsGeneral()
    }
}


fun JwsGeneral.toJwsFlattened(): List<JwsFlattened> =
    signatures.map {
        JwsFlattened(
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
            payload = this.payload,
            plainSignature = it.plainSignature
        )
    }
