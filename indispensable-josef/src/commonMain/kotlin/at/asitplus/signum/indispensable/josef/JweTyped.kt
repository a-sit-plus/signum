package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

suspend inline fun <J : JWE, reified P, reified A> J.decrypted(noinline decryptor: decryptorFun): JweTyped<J, P, A> =
    JweTyped(
        this,
        JweTyped.getPayload<P>(decryptor, this).getOrThrow(),
        JweTyped.getAdditionalAuthenticatedData<A>(this).getOrThrow()
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

    companion object {
        suspend inline fun <reified P> getPayload(
            noinline decryptor: decryptorFun,
            jwe: JWE
        ): KmmResult<P> = runCatching {
            joseCompliantSerializer.decodeFromString<P>(decryptor(jwe).decodeToString())
        }.wrap()

        inline fun <reified A> getAdditionalAuthenticatedData(
            jwe: JWE
        ): KmmResult<A?> = runCatching {
            when (jwe) {
                is JweCompact -> null
                is JweGeneral -> jwe.additionalAuthenticatedData
                is JweFlattened -> jwe.additionalAuthenticatedData
            }?.decodeToString()?.let {
                joseCompliantSerializer.decodeFromString<A>(it)
            }
        }.wrap()
    }
}
