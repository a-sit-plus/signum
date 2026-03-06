package at.asitplus.signum.indispensable.josef


data class JwsCompact(
    val protected: ByteArray,
    override val payload: ByteArray,
    val signature: ByteArray,
) : JWS() {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JwsCompact

        if (!protected.contentEquals(other.protected)) return false
        if (!payload.contentEquals(other.payload)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = protected.contentHashCode()
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

fun JwsCompact.toJwsFlattened(): JwsFlattened = JwsFlattened(
    plainProtectedHeader = protected,
    unprotectedHeader = null,
    payload = payload,
    plainSignature = signature,
)