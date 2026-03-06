package at.asitplus.signum.indispensable.josef


data class JwsCompact(
    val protected: ByteArray,
    override val payload: ByteArray,
    val signature: ByteArray,
) : JWS() {
    fun toJwsFlattened(): JwsFlattened = JwsFlattened(
        plainProtectedHeader = protected,
        unprotectedHeader = null,
        payload = payload,
        plainSignature = signature,
    )
}