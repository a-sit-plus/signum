package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.JwsTyped.Companion.invoke
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.serializer

typealias JwsCompactTyped<P> = JwsTyped<JwsCompact, P>
typealias JwsFlattenedTyped<P> = JwsTyped<JwsFlattened, P>
typealias JwsGeneralTyped<P> = JwsTyped<JwsGeneral, P>

fun <P> JwsCompactTyped<P>.toJwsFlattenedTyped() = JwsFlattenedTyped(this.jws.toJwsFlattened(), this.payload)
fun <P> JwsFlattenedTyped<P>.toJwsCompactTyped() = JwsCompactTyped(this.jws.toJwsCompact(), this.payload)
fun <P> JwsGeneralTyped<P>.toJwsFlattenedTyped() = this.jws.toJwsFlattened().map { JwsFlattenedTyped(it, this.payload) }

inline fun <reified P, J : JWS> J.typed(): JwsTyped<J, P> =
    JwsTyped(this, getPayload<P>().getOrThrow())

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JWS]. Useful when [payload] type is known as part of the contract.
 * All communication over the wire should use [jws] only!
 *
 * While the constructor can be used the different [invoke]s are recommended.
 * For convenience also see the typealiases
 */
data class JwsTyped<out J : JWS, out P>(
    val jws: J, val payload: P
) {
    override fun toString() = jws.toString()

    companion object {
        inline operator fun <reified P> invoke(base64UrlString: String) =
            JwsCompact.parse<P>(base64UrlString).getOrThrow().let { (jws, payload) -> JwsTyped(jws, payload) }

        inline operator fun <reified P> invoke(jwsFlattened: List<JwsFlattened>): JwsTyped<JwsGeneral, P> =
            jwsFlattened.toJwsGeneral().typed()

        /**
         * Creates [JwsCompact]. [protectedHeader] must form a valid [JwsHeader].
         */
        suspend inline operator fun <reified P> invoke(
            protectedHeader: JwsHeader, payload: P, noinline signer: suspend (ByteArray) -> ByteArray
        ): JwsCompactTyped<P> {
            val plainPayload = joseCompliantSerializer.encodeToString(
                joseCompliantSerializer.serializersModule.serializer(), payload
            ).encodeToByteArray()
            return JwsCompactTyped(
                JwsCompact.invoke(protectedHeader = protectedHeader, payload = plainPayload, signer = signer), payload
            )
        }

        /**
         * Creates a flattened JWS from protected and unprotected header fragments.
         * The fragments may be partial, but their merged content must form a valid [JwsHeader].
         */
        suspend inline operator fun <reified P> invoke(
            protectedHeader: JwsHeader.Part?,
            unprotectedHeader: JwsHeader.Part?,
            payload: P,
            noinline signer: suspend (ByteArray) -> ByteArray
        ): JwsFlattenedTyped<P> {
            val plainPayload = joseCompliantSerializer.encodeToString(
                joseCompliantSerializer.serializersModule.serializer(), payload
            ).encodeToByteArray()
            return JwsFlattenedTyped(
                JwsFlattened(
                    protectedHeader, unprotectedHeader, plainPayload, signer = signer
                ), payload
            )
        }
    }
}
