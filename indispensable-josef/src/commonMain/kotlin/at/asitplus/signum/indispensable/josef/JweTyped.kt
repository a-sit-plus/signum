package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer

suspend inline fun <J : JWE, reified P> J.decrypted(noinline decryptor: decryptorFun): JweTyped<J, P> =
    JweTyped(
        this,
        JweTyped.getPayload<P>(decryptor, this).getOrThrow()
    )

typealias JweCompactTyped<P> = JweTyped<JweCompact, P>
typealias JweFlattenedTyped<P> = JweTyped<JweFlattened, P>
typealias JweGeneralTyped<P> = JweTyped<JweGeneral, P>

typealias decryptorFun = suspend (JWE) -> ByteArray

/**
 * Data class that holds both encrypted over-the-wire format [JWE]
 * and the decrypted data class.
 *
 * Communication over-the-wire should use [JweTyped.jwe] only!
 */
data class JweTyped<out J : JWE, out P>(
    val jwe: J,
    val payload: P,
) {
    override fun toString() = jwe.toString()

    companion object {
        suspend inline fun <reified P> getPayload(
            noinline decryptor: decryptorFun,
            jwe: JWE
        ): KmmResult<P> = runCatching {
            joseCompliantSerializer.decodeFromString<P>(decryptor(jwe).decodeToString())
        }.wrap()
    }
}
