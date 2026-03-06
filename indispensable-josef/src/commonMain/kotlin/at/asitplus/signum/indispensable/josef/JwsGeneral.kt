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
