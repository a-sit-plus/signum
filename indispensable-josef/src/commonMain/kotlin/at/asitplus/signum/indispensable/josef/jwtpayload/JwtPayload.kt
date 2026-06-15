package at.asitplus.signum.indispensable.josef.jwtpayload

import at.asitplus.propigator.json.JsonBackingCodec
import at.asitplus.propigator.json.JsonObjectBacked
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

/**
 * Marker class identifying data classes which are valid JWT-Payloads.
 *
 * This class does not declare any functionality and exists solely for
 * type identification.
 */
abstract class JwtPayload(
    raw: JsonObject,
    json: Json = joseCompliantSerializer,
) : JsonObjectBacked(raw, JsonBackingCodec(json))