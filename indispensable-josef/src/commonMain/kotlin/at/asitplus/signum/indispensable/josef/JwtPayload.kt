package at.asitplus.signum.indispensable.josef

import at.asitplus.propigator.json.JsonBackingCodec
import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.propigator.json.jsonSlice
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Base class for all valid JWT-Payloads
 */
open class JwtPayload(
    raw: JsonObject,
    json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json)) {
    val jwtBaseClaims: JwtBaseClaims by jsonSlice()
}