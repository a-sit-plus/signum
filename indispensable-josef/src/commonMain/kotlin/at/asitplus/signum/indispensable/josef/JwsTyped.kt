package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json

/**
 * Wrapper for [at.asitplus.signum.indispensable.josef.JWS]. Useful when [payload] type is known as part of the contract.
 * All communication over the wire should use [jws] only!
 * Serialization is not recommended but does work. See [JwsTypedSerializerTemplate]
 *
 * While the constructor can be used the different [invoke]s are recommended.
 * For convenience also see the typealiases
 */
sealed class JwsTyped<out J : JWS, out P, out H : JwsHeaderBase> {
    abstract val jws: J
    abstract val payload: P

    final override fun toString() = jws.toString()

    companion object {
        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            base64UrlString: String,
            serialFormat: Json = joseCompliantSerializer,
        ) = JwsCompactTyped<P, H>(base64UrlString, serialFormat)

        inline operator fun <reified P, reified H : JwsHeaderBase> invoke(
            jwsFlattened: List<JwsFlattened>,
            serialFormat: Json = joseCompliantSerializer,
        ): JwsTyped<JwsGeneral, P, H> = JwsGeneralTyped<P, H>(jwsFlattened, serialFormat)

    }
}
