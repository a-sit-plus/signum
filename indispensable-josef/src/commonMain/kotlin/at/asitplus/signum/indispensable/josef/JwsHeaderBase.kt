package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import at.asitplus.signum.indispensable.io.CertificateChainBase64Serializer
import at.asitplus.signum.indispensable.josef.JwsHeader.SerialNames
import at.asitplus.signum.indispensable.pki.CertificateChain
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Base-Claims defined in RFC7515 which build the basis for
 * JWS Headers none of which are required.
 *
 * `@SerialName` annotations are just for convenience and
 * ARE NOT BEING INHERITED to the implementing class!
 *
 * See [RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515)
 */
interface JwsHeaderBase {
    /**
     * The "kid" (key ID) Header Parameter is a hint indicating which key
     * was used to secure the JWS.  This parameter allows originators to
     * explicitly signal a change of key to recipients.  The structure of
     * the "kid" value is unspecified.  Its value MUST be a case-sensitive
     * string.  Use of this Header Parameter is OPTIONAL.
     *
     * When used with a JWK, the "kid" value is used to match a JWK "kid"
     * parameter value.
     */
    @SerialName(SerialNames.KEY_ID)
    val keyId: String?

    /**
     * The "typ" (type) Header Parameter is used by JWS applications to
     * declare the media type (IANA.MediaTypes) of this complete JWS.  This
     * is intended for use by the application when more than one kind of
     * object could be present in an application data structure that can
     * contain a JWS; the application can use this value to disambiguate
     * among the different kinds of objects that might be present.  It will
     * typically not be used by applications when the kind of object is
     * already known.  This parameter is ignored by JWS implementations; any
     * processing of this parameter is performed by the JWS application.
     * Use of this Header Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.TYPE)
    val type: String?

    /**
     * The "alg" (algorithm) Header Parameter identifies the cryptographic
     * algorithm used to secure the JWS.  The JWS Signature value is not
     * valid if the "alg" value does not represent a supported algorithm or
     * if there is not a key for use with that algorithm associated with the
     * party that digitally signed or MACed the content.  "alg" values
     * should either be registered in the IANA "JSON Web Signature and
     * Encryption Algorithms" registry established by (JWA) or be a value
     * that contains a Collision-Resistant Name.  The "alg" value is a case-
     * sensitive ASCII string containing a StringOrURI value.  This Header
     * Parameter MUST be present and MUST be understood and processed by
     * implementations.
     */
    @SerialName(SerialNames.ALGORITHM)
    val algorithm: JwsAlgorithm

    /**
     * The "cty" (content type) Header Parameter is used by JWS applications
     * to declare the media type (IANA.MediaTypes) of the secured content
     * (the payload).  This is intended for use by the application when more
     * than one kind of object could be present in the JWS Payload; the
     * application can use this value to disambiguate among the different
     * kinds of objects that might be present.  It will typically not be
     * used by applications when the kind of object is already known.  This
     * parameter is ignored by JWS implementations; any processing of this
     * parameter is performed by the JWS application.  Use of this Header
     * Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.CONTENT_TYPE)
    val contentType: String?

    /**
     * The "x5c" (X.509 certificate chain) Header Parameter contains the
     * X.509 public key certificate or certificate chain (RFC5280)
     * corresponding to the key used to digitally sign the JWS.  The
     * certificate or certificate chain is represented as a JSON array of
     * certificate value strings.  Each string in the array is a
     * base64-encoded (Section 4 of (RFC4648) -- not base64url-encoded) DER
     * (ITU.X690.2008) PKIX certificate value.  The certificate containing
     * the public key corresponding to the key used to digitally sign the
     * JWS MUST be the first certificate.  This MAY be followed by
     * additional certificates, with each subsequent certificate being the
     * one used to certify the previous one.  The recipient MUST validate
     * the certificate chain according to RFC 5280 (RFC5280) and consider
     * the certificate or certificate chain to be invalid if any validation
     * failure occurs.  Use of this Header Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.CERTIFICATE_CHAIN)
    @Serializable(with = CertificateChainBase64Serializer::class)
    val certificateChain: CertificateChain?

    /**
     * The "jwk" (JSON Web Key) Header Parameter is the public key that
     * corresponds to the key used to digitally sign the JWS.  This key is
     * represented as a JSON Web Key (JWK).  Use of this Header Parameter is
     * OPTIONAL.
     */
    @SerialName(SerialNames.JSON_WEB_KEY)
    val jsonWebKey: JsonWebKey?

    /**
     * The "jku" (JWK Set URL) Header Parameter is a URI (RFC3986) that
     * refers to a resource for a set of JSON-encoded public keys, one of
     * which corresponds to the key used to digitally sign the JWS.  The
     * keys MUST be encoded as a JWK Set (JWK).  The protocol used to
     * acquire the resource MUST provide integrity protection; an HTTP GET
     * request to retrieve the JWK Set MUST use Transport Layer Security
     * (TLS) (RFC2818) (RFC5246); and the identity of the server MUST be
     * validated, as per Section 6 of RFC 6125 (RFC6125).  Also, see
     * Section 8 on TLS requirements.  Use of this Header Parameter is
     * OPTIONAL.
     */
    @SerialName(SerialNames.JSON_WEB_KEY_SET_URL)
    val jsonWebKeySetUrl: String?

    /**
     * The "x5u" (X.509 URL) Header Parameter is a URI (RFC3986) that refers
     * to a resource for the X.509 public key certificate or certificate
     * chain (RFC5280) corresponding to the key used to digitally sign the
     * JWS.  The identified resource MUST provide a representation of the
     * certificate or certificate chain that conforms to RFC 5280 (RFC5280)
     * in PEM-encoded form, with each certificate delimited as specified in
     * Section 6.1 of RFC 4945 (RFC4945).  The certificate containing the
     * public key corresponding to the key used to digitally sign the JWS
     * MUST be the first certificate.  This MAY be followed by additional
     * certificates, with each subsequent certificate being the one used to
     * certify the previous one.  The protocol used to acquire the resource
     * MUST provide integrity protection; an HTTP GET request to retrieve
     * the certificate MUST use TLS (RFC2818] [RFC5246); and the identity of
     * the server MUST be validated, as per Section 6 of RFC 6125 (RFC6125).
     * Also, see Section 8 on TLS requirements.  Use of this Header
     * Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.CERTIFICATE_URL)
    val certificateUrl: String?

    /**
     * The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
     * base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
     * encoding of the X.509 certificate (RFC5280) corresponding to the key
     * used to digitally sign the JWS.  Note that certificate thumbprints
     * are also sometimes known as certificate fingerprints.  Use of this
     * Header Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.CERTIFICATE_SHA1_THUMBPRINT)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha1Thumbprint: ByteArray?

    /**
     * The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
     * Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
     * of the DER encoding of the X.509 certificate (RFC5280) corresponding
     * to the key used to digitally sign the JWS.  Note that certificate
     * thumbprints are also sometimes known as certificate fingerprints.
     * Use of this Header Parameter is OPTIONAL.
     */
    @SerialName(SerialNames.CERTIFICATE_SHA256_THUMBPRINT)
    @Serializable(with = ByteArrayBase64UrlSerializer::class)
    val certificateSha256Thumbprint: ByteArray?

    /**
     * "crit" (Critical) Header Parameter
     * The "crit" (critical) Header Parameter indicates that extensions to
     * this specification and/or [JWA] are being used that MUST be
     * understood and processed.  Its value is an array listing the Header
     * Parameter names present in the JOSE Header that use those extensions.
     * If any of the listed extension Header Parameters are not understood
     * and supported by the recipient, then the JWS is invalid.
     */
    val crit: List<String>?
}
