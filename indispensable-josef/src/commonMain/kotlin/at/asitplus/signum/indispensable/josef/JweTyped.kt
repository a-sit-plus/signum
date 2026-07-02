package at.asitplus.signum.indispensable.josef

suspend inline fun <J : JWE, reified P, reified A> J.decrypted(noinline decryptor: decryptorFun): JweTyped<J, P, A> =
    JweTyped(
        this,
        this.getPayload<P>(decryptor).getOrThrow(),
        this.getAdditionalAuthenticatedData<A>().getOrThrow()
    )

typealias JweCompactTyped<P, A> = JweTyped<JweCompact, P, A>
typealias JweFlattenedTyped<P, A> = JweTyped<JweFlattened, P, A>
typealias JweGeneralTyped<P, A> = JweTyped<JweGeneral, P, A>

typealias decryptorFun = suspend (JWE) -> ByteArray

/**
 * Data class that holds both encrypted over-the-wire format [JWE]
 * and the decrypted data class.
 *
 * Communication over-the-wire should use [JweTyped.jwe] only!
 */
data class JweTyped<out J : JWE, out P, out A>(
    val jwe: J,
    val payload: P,
    val additionalAuthenticatedData: A?,
) {
    override fun toString() = jwe.toString()
}
