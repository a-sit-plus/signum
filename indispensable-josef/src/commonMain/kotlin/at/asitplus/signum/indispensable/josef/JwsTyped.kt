package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.serializer

typealias JwsCompactTyped<P> = JwsTyped<JwsCompact, P>
typealias JwsFlattenedTyped<P> = JwsTyped<JwsFlattened, P>
typealias JwsGeneralTyped<P> = JwsTyped<JwsGeneral, P>

/**
 * Convenience Serializer Template to serialize through wrapper and
 * only serialize [JwsTyped.jws].
 */
class JwsTypedSerializerTemplate<J : JWS, P>(
    jwsSerializer: KSerializer<J>,
    private val payloadSerializer: KSerializer<P>,
) : TransformingSerializerTemplate<JwsTyped<J, P>, J>(
    parent = jwsSerializer,
    encodeAs = { it.jws },
    decodeAs = { jws -> JwsTyped(jws, jws.getPayload(payloadSerializer).getOrThrow()) }
)

fun <P> JwsCompactTyped<P>.toJwsFlattenedTyped() = JwsFlattenedTyped(this.jws.toJwsFlattened(), this.payload)
fun <P> JwsFlattenedTyped<P>.toJwsCompactTyped() = JwsCompactTyped(this.jws.toJwsCompact(), this.payload)
fun <P> JwsGeneralTyped<P>.toJwsFlattenedTyped() = this.jws.toJwsFlattened().map { JwsFlattenedTyped(it, this.payload) }

inline fun <J : JWS, reified P> J.typed(): JwsTyped<J, P> =
    JwsTyped(this, getPayload<P>().getOrThrow())

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JWS]. Useful when [payload] type is known as part of the contract.
 * All communication over the wire should use [jws] only!
 * Serialization is not recommended but does work. See [JwsTypedSerializerTemplate]
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

        /** Creates a flattened JWS with the requested [unprotectedMembers]. */
        suspend inline fun <reified P> flattened(
            header: JwsHeader,
            payload: P,
            unprotectedMembers: Set<String> = emptySet(),
            noinline signer: suspend (ByteArray) -> ByteArray
        ): JwsFlattenedTyped<P> {
            val plainPayload = joseCompliantSerializer.encodeToString(
                joseCompliantSerializer.serializersModule.serializer(), payload
            ).encodeToByteArray()
            return JwsFlattenedTyped(
                JwsFlattened(header, plainPayload, unprotectedMembers, signer), payload
            )
        }
    }
}
