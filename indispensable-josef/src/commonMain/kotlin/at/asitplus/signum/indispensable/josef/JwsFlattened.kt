package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.ByteArrayUtf8Serializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


@Serializable
data class JwsFlattened(
    @Serializable(ByteArrayUtf8Serializer::class)
    @SerialName(SerialNames.PROTECTED)
    val plainProtectedHeader: ByteArray? = null,
    @SerialName(SerialNames.HEADER)
    val unprotectedHeader: JwsHeader.Part? = null,
    @Serializable(ByteArrayBase64UrlSerializer::class)
    @SerialName(SerialNames.PAYLOAD)
    override val payload: ByteArray,
    @Serializable(ByteArrayBase64UrlSerializer::class)
    @SerialName(SerialNames.SIGNATURE)
    val plainSignature: ByteArray
) : JWS() {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsFlattened

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (unprotectedHeader != other.unprotectedHeader) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!plainSignature.contentEquals(other.plainSignature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader?.contentHashCode() ?: 0
        result = 31 * result + (unprotectedHeader?.hashCode() ?: 0)
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + plainSignature.contentHashCode()
        return result
    }

    val jwsHeader by lazy { JwsHeader.fromParts(plainProtectedHeader, unprotectedHeader) }

    companion object {
        fun invoke(
            protectedHeader: JwsHeader.Part,
            unprotectedHeader: JwsHeader.Part = JwsHeader.Part(),
            payload: ByteArray,
            signer: (JwsAlgorithm, ByteArray) -> ByteArray
        ): JwsFlattened {
            val jwsHeader = JwsHeader.fromParts(protectedHeader, unprotectedHeader)
            val plainProtectedHeader = JwsProtectedHeaderSerializer.encodeToByteArray(protectedHeader)
            return JwsFlattened(
                plainProtectedHeader,
                unprotectedHeader,
                payload,
                signer(jwsHeader.algorithm, getSignatureInput(plainProtectedHeader, payload))
            )
        }
    }
}

fun JwsFlattened.toJwsCompact(): JwsCompact =
    JwsCompact(
        plainProtectedHeader = plainProtectedHeader!!,
        payload = payload,
        plainSignature = plainSignature,
    )

fun List<JwsFlattened>.toJwsGeneral(): JwsGeneral {
    val payload = this[0].payload
    val signatures = this.map {
        require(payload.contentEqualsIfArray(it.payload)) {
            "Additional signed JWS payload must match existing payload"
        }
        SignatureElement(
            plainSignature = it.plainSignature,
            plainProtectedHeader = it.plainProtectedHeader,
            unprotectedHeader = it.unprotectedHeader,
        )
    }
    return JwsGeneral(
        payload = payload,
        signatures = signatures
    )
}
