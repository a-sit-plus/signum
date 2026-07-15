package at.asitplus.signum.indispensable.josef

import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Base class for all valid JWT-Payloads
 *
 * Usage Example:
 *
 * ```
 * data class FooPayload(
 *     private val raw: JsonObject,
 *     private val json: Json = joseCompliantSerializer,
 * ) : JwtPayload(raw, json) {
 *   val foo: Foo? by nullableJsonProperty("foo")
 *   val barSlice: Bar by jsonSlice()
 * }
 * ```
 *
 */
open class JwtPayload(
    raw: JsonObject,
    json: Json = joseCompliantSerializer
) : JsonObjectBacked(raw, json) {
    val jwtBaseClaims: JwtBaseClaims by jsonSlice()
}