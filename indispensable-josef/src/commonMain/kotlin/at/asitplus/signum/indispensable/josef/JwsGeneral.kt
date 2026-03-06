package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.contentEqualsIfArray

data class JwsGeneral(
    val payload: ByteArray,
    val signatures: List<SignatureElement>
) {
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
