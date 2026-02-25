package at.asitplus.signum.indispensable.josef

import kotlinx.serialization.Serializable

/**
 * [RFC 7515 Sec 7.2.1](https://www.rfc-editor.org/rfc/rfc7515.html#section-7.2.1)
 * Allows multiple digital signatures and/or MACs for the same payload
 */
@Serializable(with = JwsGeneralSerializer::class)
data class JwsGeneral<P>(
    /**
     * The [payload] member MUST be present and contain the value BASE64URL(JWS Payload).
     */
    val payload: P,
    /**
     * The [signatures] member value MUST be an array of JSON objects.
     * Each object represents a signature or MAC over the JWS Payload and
     * the JWS Protected Header.
     */
    val signatures: List<SignatureElement>,
)

