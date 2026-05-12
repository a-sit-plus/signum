@file:UseSerializers(ByteArrayBase64Serializer::class)

package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.ByteArrayBase64Serializer
import at.asitplus.signum.indispensable.io.InstantLongSerializer
import at.asitplus.signum.indispensable.josef.jwtpayload.ConfirmationClaim
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.json.JsonObject
import kotlin.time.Instant

@Suppress("unused")
@Deprecated("Renamed to better reflect content", ReplaceWith("jwtpayload"))
typealias JsonWebToken = JwtClaims

/**
 * Base-Claims defined in RFC7519
 *
 * See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)
 */
@Serializable
data class JwtClaims(

    /**
     * RFC 7519: The "iss" (issuer) claim identifies the principal that issued the
     * JWT.  The processing of this claim is generally application specific.
     * The "iss" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.ISS)
    val issuer: String? = null,

    /**
     * RFC 7519: The "sub" (subject) claim identifies the principal that is the
     * subject of the JWT.  The claims in a JWT are normally statements
     * about the subject.  The subject value MUST either be scoped to be
     * locally unique in the context of the issuer or be globally unique.
     * The processing of this claim is generally application specific.  The
     * "sub" value is a case-sensitive string containing a StringOrURI
     * value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.SUB)
    val subject: String? = null,

    /**
     * RFC 7519: The "aud" (audience) claim identifies the recipients that the JWT is
     * intended for.  Each principal intended to process the JWT MUST
     * identify itself with a value in the audience claim.  If the principal
     * processing the claim does not identify itself with a value in the
     * "aud" claim when this claim is present, then the JWT MUST be
     * rejected.  In the general case, the "aud" value is an array of case-sensitive strings,
     * each containing a StringOrURI value.  In the
     * special case when the JWT has one audience, the "aud" value MAY be a
     * single case-sensitive string containing a StringOrURI value.  The
     * interpretation of audience values is generally application specific.
     * Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.AUD)
    val audience: String? = null,

    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(IanaRegistered.ClaimNames.OpenIdConnectCore.NONCE)
    val nonce: String? = null,

    /**
     * RFC 7519: The "nbf" (not before) claim identifies the time before which the JWT
     * MUST NOT be accepted for processing.  The processing of the "nbf"
     * claim requires that the current date/time MUST be after or equal to
     * the not-before date/time listed in the "nbf" claim.  Implementers MAY
     * provide for some small leeway, usually no more than a few minutes, to
     * account for clock skew.  Its value MUST be a number containing a
     * NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.NBF)
    @Serializable(with = InstantLongSerializer::class)
    val notBefore: Instant? = null,

    /**
     * RFC 7519: The "iat" (issued at) claim identifies the time at which the JWT was
     * issued.  This claim can be used to determine the age of the JWT.  Its
     * value MUST be a number containing a NumericDate value.  Use of this
     * claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.IAT)
    @Serializable(with = InstantLongSerializer::class)
    val issuedAt: Instant? = null,

    /**
     * RFC 7519: The "exp" (expiration time) claim identifies the expiration time on
     * or after which the JWT MUST NOT be accepted for processing.  The
     * processing of the "exp" claim requires that the current date/time
     * MUST be before the expiration date/time listed in the "exp" claim.
     * Implementers MAY provide for some small leeway, usually no more than
     * a few minutes, to account for clock skew.  Its value MUST be a number
     * containing a NumericDate value.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant? = null,

    /**
     * RFC 7519: The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     * The identifier value MUST be assigned in a manner that ensures that
     * there is a negligible probability that the same value will be
     * accidentally assigned to a different data object; if the application
     * uses multiple issuers, collisions MUST be prevented among values
     * produced by different issuers as well.  The "jti" claim can be used
     * to prevent the JWT from being replayed.  The "jti" value is a case-sensitive string.  Use of this claim is OPTIONAL.
     */
    @SerialName(IanaRegistered.ClaimNames.RFC7519.JTI)
    val jwtId: String? = null,

    /**
     * OID4VP: This claim contains the confirmation method as defined in RFC7800. It MUST contain a JWK as defined in
     * Section 3.2 of RFC7800. This claim determines the public key for which the corresponding private key the
     * Verifier MUST proof possession of when presenting the Verifier Attestation JWT. This additional security measure
     * allows the Verifier to obtain a Verifier Attestation JWT from a trusted issuer and use it for a long time
     * independent of that issuer without the risk of an adversary impersonating the Verifier by replaying a captured
     * attestation.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(IanaRegistered.ClaimNames.RFC7800.CNF)
    val confirmationClaim: ConfirmationClaim? = null,

    /**
     * RFC 9449: The value of the HTTP method (Section 9.1 of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110))
     * of the request to which the JWT is attached.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(IanaRegistered.ClaimNames.RFC9449.HTM)
    val httpMethod: String? = null,

    /**
     * RFC 9449: The HTTP target URI (Section 7.1 of [RFC9110](https://datatracker.ietf.org/doc/html/rfc9110)) of the
     * request to which the JWT is attached, without query and fragment parts.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(IanaRegistered.ClaimNames.RFC9449.HTU)
    val httpTargetUrl: String? = null,

    /**
     * RFC 9449: Hash of the access token. The value MUST be the result of a base64url encoding (as defined in Section
     * 2 of [RFC7515](https://datatracker.ietf.org/doc/html/rfc7515)) the SHA-256 hash of the ASCII encoding of the
     * associated access token's value.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(IanaRegistered.ClaimNames.RFC9449.ATH)
    val accessTokenHash: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a human-readable name of the Wallet.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_NAME)
    val walletName: String? = null,

    /**
     * OID4VCI: OPTIONAL. String containing a URL to get further information about the Wallet and the Wallet Provider.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_LINK)
    val walletLink: String? = null,

    /**
     * EUDI TS3 WUA 1.5: version of the Wallet Solution.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_VERSION)
    val walletVersion: String? = null,

    /**
     * EUDI TS3 WUA 1.5: information about the certification achieved by the Wallet Solution.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(UnregisteredClaims.EudiTs3Claims.WALLET_SOLUTION_CERTIFICATION_INFORMATION)
    val walletSolutionCertificationInformation: String? = null,

    /**
     * EUDI TS3 WUA 1.5: status list reference for the Wallet Instance and the time until which the Wallet Provider
     * commits to maintaining the referenced status.
     */
    @Deprecated("Will be removed in the future. Please use specialized JWT-Claims class instead!", level = DeprecationLevel.WARNING)
    @SerialName(UnregisteredClaims.EudiTs3Claims.CLIENT_STATUS)
    val clientStatus: ClientStatus? = null,

    /**
     * OPTIONAL: Data class containing information for instance/unit attestation
     * See: https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications/blob/main/docs/technical-specifications/ts3-wallet-unit-attestation.md
     */
    @Deprecated("TS3 WUA 1.5 removed eudi_wallet_info from Wallet Instance Attestations.")
    @SerialName("eudi_wallet_info")
    val eudiWalletInfo: EudiWalletInfo? = null,

    /**
     * OID4VCI: OPTIONAL. Status mechanism for the Wallet Attestation as defined in ietf-oauth-status-list.
     */
    @Deprecated("TS3 WUA 1.5 replaced top-level status with client_status.")
    @SerialName("status")
    val status: JsonObject? = null,
) {
    /**
     * Claims to be used in conjunction with
     * [Propigator](https://github.com/a-sit-plus/propigator)
     * to define type-safe extensions to [JwtClaims].
     * The values of the constants are the official [SerialName]s.
     */
    object UnregisteredClaims {
        object DraftIetfOauthAttestation {
            const val CHALLENGE = "challenge"
        }
        object EudiTs3Claims {
            const val WALLET_VERSION = "wallet_version"
            const val WALLET_SOLUTION_CERTIFICATION_INFORMATION = "wallet_solution_certification_information"
            const val CLIENT_STATUS = "client_status"
            const val WALLET_NAME = "wallet_name"
            const val WALLET_LINK = "wallet_link"
            const val ATTESTED_KEYS = "attested_keys"
            const val KEY_STORAGE = "key_storage"
            const val KEY_STORAGE_STATUS = "key_storage_status"
            const val USER_AUTHENTICATION = "user_authentication"
            const val CERTIFICATION = "certification"
        }
    }
    /**
     * Claims taken from [IANA](https://www.iana.org/assignments/jwt/jwt.xhtml) to be used in conjunction with
     * [Propigator](https://github.com/a-sit-plus/propigator)
     * to define type-safe extensions to [JwtClaims].
     * The values of the constants are the official [SerialName]s.
     */
    @Suppress("UNUSED")
    object IanaRegistered {

        object ClaimNames {
            object RFC7519 {
                /**
                 * RFC7519, Section 4.1.1
                 * Issuer
                 */
                const val ISS = "iss"

                /**
                 * RFC7519, Section 4.1.2
                 * Subject
                 */
                const val SUB = "sub"

                /**
                 * RFC7519, Section 4.1.3
                 * Audience
                 */
                const val AUD = "aud"

                /**
                 * RFC7519, Section 4.1.4
                 * Expiration Time
                 */
                const val EXP = "exp"

                /**
                 * RFC7519, Section 4.1.5
                 * Not Before
                 */
                const val NBF = "nbf"

                /**
                 * RFC7519, Section 4.1.6
                 * Issued At
                 */
                const val IAT = "iat"

                /**
                 * RFC7519, Section 4.1.7
                 * JWT ID
                 */
                const val JTI = "jti"
            }

            object OpenIdConnectCore {
                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Full name
                 */
                const val NAME = "name"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Given name(s) or first name(s)
                 */
                const val GIVEN_NAME = "given_name"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Surname(s) or last name(s)
                 */
                const val FAMILY_NAME = "family_name"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Middle name(s)
                 */
                const val MIDDLE_NAME = "middle_name"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Casual name
                 */
                const val NICKNAME = "nickname"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Shorthand name by which the End-User wishes to be referred to
                 */
                const val PREFERRED_USERNAME = "preferred_username"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Profile page URL
                 */
                const val PROFILE = "profile"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Profile picture URL
                 */
                const val PICTURE = "picture"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Web page or blog URL
                 */
                const val WEBSITE = "website"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Preferred e-mail address
                 */
                const val EMAIL = "email"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * True if the e-mail address has been verified; otherwise false
                 */
                const val EMAIL_VERIFIED = "email_verified"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Gender
                 */
                const val GENDER = "gender"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Birthday
                 */
                const val BIRTHDATE = "birthdate"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Time zone
                 */
                const val ZONEINFO = "zoneinfo"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Locale
                 */
                const val LOCALE = "locale"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Preferred telephone number
                 */
                const val PHONE_NUMBER = "phone_number"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * True if the phone number has been verified; otherwise false
                 */
                const val PHONE_NUMBER_VERIFIED = "phone_number_verified"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Preferred postal address
                 */
                const val ADDRESS = "address"

                /**
                 * OpenID Connect Core 1.0, Section 5.1
                 * Time the information was last updated
                 */
                const val UPDATED_AT = "updated_at"

                /**
                 * OpenID Connect Core 1.0, Section 2
                 * Authorized party - the party to which the ID Token was issued
                 */
                const val AZP = "azp"

                /**
                 * OpenID Connect Core 1.0, Section 2RFC9449
                 * Value used to associate a Client session with an ID Token (MAY also be used for nonce values in other applications of JWTs)
                 */
                const val NONCE = "nonce"

                /**
                 * OpenID Connect Core 1.0, Section 2
                 * Time when the authentication occurred
                 */
                const val AUTH_TIME = "auth_time"

                /**
                 * OpenID Connect Core 1.0, Section 2
                 * Access Token hash value
                 */
                const val AT_HASH = "at_hash"

                /**
                 * OpenID Connect Core 1.0, Section 3.3.2.11
                 * Code hash value
                 */
                const val C_HASH = "c_hash"

                /**
                 * OpenID Connect Core 1.0, Section 2
                 * Authentication Context Class Reference
                 */
                const val ACR = "acr"

                /**
                 * OpenID Connect Core 1.0, Section 2
                 * Authentication Methods References
                 */
                const val AMR = "amr"

                /**
                 * OpenID Connect Core 1.0, Section 7.4
                 * Public key used to check the signature of an ID Token
                 */
                const val SUB_JWK = "sub_jwk"

                /**
                 * OpenID Connect Core 1.0, Section 5.6.2
                 * JSON object whose member names are the Claim Names for the Aggregated and Distributed Claims
                 */
                const val CLAIM_NAMES = "_claim_names"

                /**
                 * OpenID Connect Core 1.0, Section 5.6.2
                 * JSON object whose member names are referenced by the member values of the _claim_names member
                 */
                const val CLAIM_SOURCES = "_claim_sources"
            }

            object RFC7800 {
                /**
                 * RFC7800, Section 3.1
                 * Confirmation
                 */
                const val CNF = "cnf"
            }

            object RFC8055 {
                /**
                 * RFC8055, RFC3261
                 * SIP From tag header field parameter value
                 */
                const val SIP_FROM_TAG = "sip_from_tag"

                /**
                 * RFC8055, RFC3261
                 * SIP Date header field value
                 */
                const val SIP_DATE = "sip_date"

                /**
                 * RFC8055, RFC3261
                 * SIP Call-Id header field value
                 */
                const val SIP_CALLID = "sip_callid"

                /**
                 * RFC8055, RFC3261
                 * SIP CSeq numeric header field parameter value
                 */
                const val SIP_CSEQ_NUM = "sip_cseq_num"

                /**
                 * RFC8055, RFC3261
                 * SIP Via branch header field parameter value
                 */
                const val SIP_VIA_BRANCH = "sip_via_branch"
            }

            object RFC8225 {
                /**
                 * RFC8225, Section 5.2.1
                 * Originating Identity String
                 */
                const val ORIG = "orig"

                /**
                 * RFC8225, Section 5.2.1
                 * Destination Identity String
                 */
                const val DEST = "dest"

                /**
                 * RFC8225, Section 5.2.2
                 * Media Key Fingerprint String
                 */
                const val MKY = "mky"
            }

            object RFC8417 {
                /**
                 * RFC8417, Section 2.2
                 * Security Events
                 */
                const val EVENTS = "events"

                /**
                 * RFC8417, Section 2.2
                 * Time of Event
                 */
                const val TOE = "toe"

                /**
                 * RFC8417, Section 2.2
                 * Transaction Identifier
                 */
                const val TXN = "txn"
            }

            object RFC8443 {
                /**
                 * RFC8443, Section 3
                 * Resource Priority Header Authorization
                 */
                const val RPH = "rph"
            }

            object OpenIdConnectFrontChannelLogout {
                /**
                 * OpenID Connect Front-Channel Logout 1.0, Section 3
                 * Session ID
                 */
                const val SID = "sid"
            }

            object RFC8485 {
                /**
                 * RFC8485
                 * Vector of Trust value
                 */
                const val VOT = "vot"

                /**
                 * RFC8485
                 * Vector of Trust trustmark URL
                 */
                const val VTM = "vtm"
            }

            object RFC8588 {
                /**
                 * RFC8588
                 * Attestation level as defined in SHAKEN framework
                 */
                const val ATTEST = "attest"

                /**
                 * RFC8588
                 * Originating Identifier as defined in SHAKEN framework
                 */
                const val ORIGID = "origid"
            }

            object RFC8693 {
                /**
                 * RFC8693, Section 4.1
                 * Actor
                 */
                const val ACT = "act"

                /**
                 * RFC8693, Section 4.2
                 * Scope Values
                 */
                const val SCOPE = "scope"

                /**
                 * RFC8693, Section 4.3
                 * Client Identifier
                 */
                const val CLIENT_ID = "client_id"

                /**
                 * RFC8693, Section 4.4
                 * Authorized Actor - the party that is authorized to become the actor
                 */
                const val MAY_ACT = "may_act"
            }

            object RFC8688 {
                /**
                 * RFC8688RFC7095
                 * jCard data
                 */
                const val JCARD = "jcard"
            }

            object EtsiGsNfvSec022 {
                /**
                 * ETSI GS NFV-SEC 022 V2.7.1
                 * Number of API requests for which the access token can be used
                 */
                const val AT_USE_NBR = "at_use_nbr"
            }

            object RFC8946 {
                /**
                 * RFC8946
                 * Diverted Target of a Call
                 */
                const val DIV = "div"

                /**
                 * RFC8946
                 * Original PASSporT (in Full Form)
                 */
                const val OPT = "opt"
            }

            object W3cVerifiableCredentialsDataModel {
                /**
                 * W3C Recommendation Verifiable Credentials Data Model 1.0 - Expressing verifiable information on the Web (19 November 2019), Section 6.3.1
                 * Verifiable Credential as specified in the W3C Recommendation
                 */
                const val VC = "vc"

                /**
                 * W3C Recommendation Verifiable Credentials Data Model 1.0 - Expressing verifiable information on the Web (19 November 2019), Section 6.3.1
                 * Verifiable Presentation as specified in the W3C Recommendation
                 */
                const val VP = "vp"
            }

            object RFC9027 {
                /**
                 * RFC9027
                 * SIP Priority header field
                 */
                const val SPH = "sph"
            }

            object RFC9200 {
                /**
                 * RFC9200, Section 5.10
                 * The ACE profile a token is supposed to be used with.
                 */
                const val ACE_PROFILE = "ace_profile"

                /**
                 * RFC9200, Section 5.10
                 * "client-nonce". A nonce previously provided to the AS by the RS via the client. Used to verify token freshness when the RS cannot synchronize its clock with the AS.
                 */
                const val CNONCE = "cnonce"

                /**
                 * RFC9200, Section 5.10.3
                 * "Expires in". Lifetime of the token in seconds from the time the RS first sees it. Used to implement a weaker from of token expiration for devices that cannot synchronize their internal clocks.
                 */
                const val EXI = "exi"
            }

            object RFC7643 {
                /**
                 * RFC7643, Section 4.1.2RFC9068, Section 2.2.3.1
                 * Roles
                 */
                const val ROLES = "roles"

                /**
                 * RFC7643, Section 4.1.2RFC9068, Section 2.2.3.1
                 * Groups
                 */
                const val GROUPS = "groups"

                /**
                 * RFC7643, Section 4.1.2RFC9068, Section 2.2.3.1
                 * Entitlements
                 */
                const val ENTITLEMENTS = "entitlements"
            }

            object RFC9701 {
                /**
                 * RFC9701, Section 5
                 * Token introspection response
                 */
                const val TOKEN_INTROSPECTION = "token_introspection"
            }

            object RFC9711 {
                /**
                 * RFC9711
                 * Nonce
                 */
                const val EAT_NONCE = "eat_nonce"

                /**
                 * RFC9711
                 * Universal Entity ID
                 */
                const val UEID = "ueid"

                /**
                 * RFC9711
                 * Semipermanent UEIDs
                 */
                const val SUEIDS = "sueids"

                /**
                 * RFC9711
                 * Hardware OEM ID
                 */
                const val OEMID = "oemid"

                /**
                 * RFC9711
                 * Model identifier for hardware
                 */
                const val HWMODEL = "hwmodel"

                /**
                 * RFC9711
                 * Hardware Version Identifier
                 */
                const val HWVERSION = "hwversion"

                /**
                 * RFC9711
                 * Indicates whether the software booted was OEM authorized
                 */
                const val OEMBOOT = "oemboot"

                /**
                 * RFC9711
                 * The status of debug facilities
                 */
                const val DBGSTAT = "dbgstat"

                /**
                 * RFC9711
                 * The geographic location
                 */
                const val LOCATION = "location"

                /**
                 * RFC9711
                 * The EAT profile followed
                 */
                const val EAT_PROFILE = "eat_profile"

                /**
                 * RFC9711
                 * The section containing submodules
                 */
                const val SUBMODS = "submods"

                /**
                 * RFC9711
                 * Uptime
                 */
                const val UPTIME = "uptime"

                /**
                 * RFC9711
                 * The number of times the entity or submodule has been booted
                 */
                const val BOOTCOUNT = "bootcount"

                /**
                 * RFC9711
                 * Identifies a boot cycle
                 */
                const val BOOTSEED = "bootseed"

                /**
                 * RFC9711
                 * Certifications received as Digital Letters of Approval
                 */
                const val DLOAS = "dloas"

                /**
                 * RFC9711
                 * The name of the software running in the entity
                 */
                const val SWNAME = "swname"

                /**
                 * RFC9711
                 * The version of software running in the entity
                 */
                const val SWVERSION = "swversion"

                /**
                 * RFC9711
                 * Manifests describing the software installed on the entity
                 */
                const val MANIFESTS = "manifests"

                /**
                 * RFC9711
                 * Measurements of the software, memory configuration, and such on the entity
                 */
                const val MEASUREMENTS = "measurements"

                /**
                 * RFC9711
                 * The results of comparing software measurements to reference values
                 */
                const val MEASRES = "measres"

                /**
                 * RFC9711
                 * The intended use of the EAT
                 */
                const val INTUSE = "intuse"
            }

            object RFC9246 {
                /**
                 * RFC9246, Section 2.1.8
                 * CDNI Claim Set Version
                 */
                const val CDNIV = "cdniv"

                /**
                 * RFC9246, Section 2.1.9
                 * CDNI Critical Claims Set
                 */
                const val CDNICRIT = "cdnicrit"

                /**
                 * RFC9246, Section 2.1.10
                 * CDNI IP Address
                 */
                const val CDNIIP = "cdniip"

                /**
                 * RFC9246, Section 2.1.11
                 * CDNI URI Container
                 */
                const val CDNIUC = "cdniuc"

                /**
                 * RFC9246, Section 2.1.12
                 * CDNI Expiration Time Setting for Signed Token Renewal
                 */
                const val CDNIETS = "cdniets"

                /**
                 * RFC9246, Section 2.1.13
                 * CDNI Signed Token Transport Method for Signed Token Renewal
                 */
                const val CDNISTT = "cdnistt"

                /**
                 * RFC9246, Section 2.1.14
                 * CDNI Signed Token Depth
                 */
                const val CDNISTD = "cdnistd"
            }

            object RFC9321 {
                /**
                 * RFC9321, Section 3.2.3
                 * Signature Validation Token
                 */
                const val SIG_VAL_CLAIMS = "sig_val_claims"
            }

            object RFC9396 {
                /**
                 * RFC9396, Section 9.1
                 * The claim authorization_details contains a JSON array of JSON objects representing the rights of the access token. Each JSON object contains the data to specify the authorization requirements for a certain type of resource.
                 */
                const val AUTHORIZATION_DETAILS = "authorization_details"
            }

            object OpenIdIdentityAssuranceSchemaDefinition {
                /**
                 * OpenID Identity Assurance Schema Definition 1.0, Section 5
                 * A structured claim containing end-user claims and the details of how those end-user claims were assured.
                 */
                const val VERIFIED_CLAIMS = "verified_claims"
            }

            object OpenIdConnectForIdentityAssuranceClaimsRegistration {
                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * A structured claim representing the end-user's place of birth.
                 */
                const val PLACE_OF_BIRTH = "place_of_birth"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * String array representing the end-user's nationalities.
                 */
                const val NATIONALITIES = "nationalities"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * Family name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the family name(s) later in life for any reason. Note that in some cultures, people can have multiple family names or no family name; all can be present, with the names being separated by space characters.
                 */
                const val BIRTH_FAMILY_NAME = "birth_family_name"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * Given name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the given name later in life for any reason. Note that in some cultures, people can have multiple given names; all can be present, with the names being separated by space characters.
                 */
                const val BIRTH_GIVEN_NAME = "birth_given_name"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * Middle name(s) someone has when they were born, or at least from the time they were a child. This term can be used by a person who changes the middle name later in life for any reason. Note that in some cultures, people can have multiple middle names; all can be present, with the names being separated by space characters. Also note that in some cultures, middle names are not used.
                 */
                const val BIRTH_MIDDLE_NAME = "birth_middle_name"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * End-user's salutation, e.g., "Mr"
                 */
                const val SALUTATION = "salutation"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * End-user's title, e.g., "Dr"
                 */
                const val TITLE = "title"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * End-user's mobile phone number formatted according to ITU-T recommendation E.164
                 */
                const val MSISDN = "msisdn"

                /**
                 * OpenID Connect for Identity Assurance Claims Registration 1.0, Section 4
                 * Stage name, religious name or any other type of alias/pseudonym with which a person is known in a specific context besides its legal name.
                 */
                const val ALSO_KNOWN_AS = "also_known_as"
            }

            object RFC9449 {
                /**
                 * RFC9449, Section 4.2
                 * The HTTP method of the request
                 */
                const val HTM = "htm"

                /**
                 * RFC9449, Section 4.2
                 * The HTTP URI of the request (without query and fragment parts)
                 */
                const val HTU = "htu"

                /**
                 * RFC9449, Section 4.2
                 * The base64url-encoded SHA-256 hash of the ASCII encoding of the associated access token's value
                 */
                const val ATH = "ath"
            }

            object RFC9447 {
                /**
                 * RFC9447
                 * Authority Token Challenge
                 */
                const val ATC = "atc"
            }

            object RFC9493 {
                /**
                 * RFC9493, Section 4.1
                 * Subject Identifier
                 */
                const val SUB_ID = "sub_id"
            }

            object RFC9795 {
                /**
                 * RFC9795
                 * Rich Call Data Information
                 */
                const val RCD = "rcd"

                /**
                 * RFC9795
                 * Rich Call Data Integrity Information
                 */
                const val RCDI = "rcdi"

                /**
                 * RFC9795
                 * Call Reason
                 */
                const val CRN = "crn"
            }

            object RFC9475 {
                /**
                 * RFC9475
                 * Message Integrity Information
                 */
                const val MSGI = "msgi"
            }

            object RFC9560 {
                /**
                 * RFC9560, Section 3.1.5.1
                 * This claim describes the set of RDAP query purposes that are available to an identity that is presented for access to a protected RDAP resource.
                 */
                const val RDAP_ALLOWED_PURPOSES = "rdap_allowed_purposes"

                /**
                 * RFC9560, Section 3.1.5.2
                 * This claim contains a JSON boolean literal that describes a "do not track" request for server-side tracking, logging, or recording of an identity that is presented for access to a protected RDAP resource.
                 */
                const val RDAP_DNT_ALLOWED = "rdap_dnt_allowed"
            }

            object FastReadableGeographicalHashing {
                /**
                 * Fast and Readable Geographical Hashing (CTA-5009)
                 * Geohash String or Array
                 */
                const val GEOHASH = "geohash"
            }

            object RFC9901 {
                /**
                 * RFC9901, Section 4.2.4.1
                 * Digests of Disclosures for object properties
                 */
                const val SD = "_sd"

                /**
                 * RFC9901, Section 4.2.4.2
                 * Digest of the Disclosure for an array element
                 */
                const val ELLIPSIS = "..."

                /**
                 * RFC9901, Section 4.1.1
                 * Hash algorithm used to generate Disclosure digests and digest over presentation
                 */
                const val SD_ALG = "_sd_alg"

                /**
                 * RFC9901, Section 4.3
                 * Digest of the SD-JWT to which the KB-JWT is tied
                 */
                const val SD_HASH = "sd_hash"
            }

            object ThreeGppTs29510 {
                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * PLMN ID of the NF service consumer
                 */
                const val CONSUMER_PLMN_ID = "consumerPlmnId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * SNPN ID of the NF service consumer
                 */
                const val CONSUMER_SNPN_ID = "consumerSnpnId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * PLMN ID of the NF service producer
                 */
                const val PRODUCER_PLMN_ID = "producerPlmnId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * SNPN ID of the NF service producer
                 */
                const val PRODUCER_SNPN_ID = "producerSnpnId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * list of S-NSSAIs of the NF service producer which are authorized for the NF service consumer
                 */
                const val PRODUCER_SNSSAI_LIST = "producerSnssaiList"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * List of NSIs of the NF service producer which are authorized for the NF service consumer
                 */
                const val PRODUCER_NSI_LIST = "producerNsiList"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * NF Set ID of the NF service producer
                 */
                const val PRODUCER_NF_SET_ID = "producerNfSetId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * NF Service Set ID of the NF Service Producer
                 */
                const val PRODUCER_NF_SERVICE_SET_ID = "producerNfServiceSetId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * NF Instance ID of the source NF
                 */
                const val SOURCE_NF_INSTANCE_ID = "sourceNfInstanceId"

                /**
                 * 3GPP TS 29.510, Clause 6.3.5.2.4
                 * Analytics IDs
                 */
                const val ANALYTICS_ID_LIST = "analyticsIdList"
            }

            object ThreeGppTs29222 {
                /**
                 * 3GPP TS 29.222, Clause 8.5.4.2.8
                 * Contains the identifier of the resource owner, e.g., GPSI as specified in clause 5.3.2 of 3GPP TS 29.571.
                 */
                const val RES_OWNER_ID = "resOwnerId"
            }

            object RfcIetfRatsMsgWrap22 {
                /**
                 * RFC-ietf-rats-msg-wrap-22, Sections 3.1, 3.3
                 * A RATS Conceptual Message Wrapper
                 */
                const val CMW = "cmw"
            }

            object OpenIdFederation {
                /**
                 * OpenID Federation 1.0, Section 13.1
                 * JSON Web Key Set
                 */
                const val JWKS = "jwks"

                /**
                 * OpenID Federation 1.0, Section 13.2
                 * Metadata object
                 */
                const val METADATA = "metadata"

                /**
                 * OpenID Federation 1.0, Section 13.3
                 * Constraints object
                 */
                const val CONSTRAINTS = "constraints"

                /**
                 * OpenID Federation 1.0, Section 13.4
                 * List of Claims in this JWT defined by extensions to this kind of JWT that MUST be understood and processed
                 */
                const val CRIT = "crit"

                /**
                 * OpenID Federation 1.0, Section 13.5
                 * Reference
                 */
                const val REF = "ref"

                /**
                 * OpenID Federation 1.0, Section 13.6
                 * Delegation
                 */
                const val DELEGATION = "delegation"

                /**
                 * OpenID Federation 1.0, Section 13.7
                 * URI referencing a logo
                 */
                const val LOGO_URI = "logo_uri"

                /**
                 * OpenID Federation 1.0, Section 3.2
                 * Authority Hints
                 */
                const val AUTHORITY_HINTS = "authority_hints"

                /**
                 * OpenID Federation 1.0, Section 3.2
                 * Trust Anchor Hints
                 */
                const val TRUST_ANCHOR_HINTS = "trust_anchor_hints"

                /**
                 * OpenID Federation 1.0, Section 3.2
                 * Trust Marks
                 */
                const val TRUST_MARKS = "trust_marks"

                /**
                 * OpenID Federation 1.0, Section 3.2
                 * Trust Mark Issuers
                 */
                const val TRUST_MARK_ISSUERS = "trust_mark_issuers"

                /**
                 * OpenID Federation 1.0, Section 3.2
                 * Trust Mark Owners
                 */
                const val TRUST_MARK_OWNERS = "trust_mark_owners"

                /**
                 * OpenID Federation 1.0, Section 3.3
                 * Metadata Policy object
                 */
                const val METADATA_POLICY = "metadata_policy"

                /**
                 * OpenID Federation 1.0, Section 3.3
                 * Critical Metadata Policy Operators
                 */
                const val METADATA_POLICY_CRIT = "metadata_policy_crit"

                /**
                 * OpenID Federation 1.0, Section 3.3
                 * Source Endpoint URL
                 */
                const val SOURCE_ENDPOINT = "source_endpoint"

                /**
                 * OpenID Federation 1.0, Section 5.2.1
                 * Array of JWK values in a JWK Set
                 */
                const val KEYS = "keys"

                /**
                 * OpenID Federation 1.0, Section 7.1
                 * Trust Mark Type Identifier
                 */
                const val TRUST_MARK_TYPE = "trust_mark_type"

                /**
                 * OpenID Federation 1.0, Section 8.3.2
                 * Trust Chain
                 */
                const val TRUST_CHAIN = "trust_chain"

                /**
                 * OpenID Federation 1.0, Section 12.2.3
                 * Trust Anchor ID
                 */
                const val TRUST_ANCHOR = "trust_anchor"
            }
        }

        object ConfirmationMethods {
            object RFC7800 {
                /**
                 * RFC7800, Section 3.2
                 * JSON Web Key Representing Public Key
                 */
                const val JWK = "jwk"

                /**
                 * RFC7800, Section 3.3
                 * Encrypted JSON Web Key
                 */
                const val JWE = "jwe"

                /**
                 * RFC7800, Section 3.4
                 * Key Identifier
                 */
                const val KID = "kid"

                /**
                 * RFC7800, Section 3.5
                 * JWK Set URL
                 */
                const val JKU = "jku"
            }

            object RFC8705 {
                /**
                 * RFC8705, Section 3.1
                 * X.509 Certificate SHA-256 Thumbprint
                 */
                const val X5T = "x5t#S256"
            }

            object RFC9203 {
                /**
                 * RFC9203, Section 3.2.1
                 * OSCORE_Input_Material carrying the parameters for using OSCORE per-message security with implicit key confirmation
                 */
                const val OSC = "osc"
            }

            object RFC9449 {
                /**
                 * RFC9449, Section 6
                 * JWK SHA-256 Thumbprint
                 */
                const val JKT = "jkt"
            }
        }
    }
}

@Serializable
data class ClientStatus(
    /**
     * Status list reference as specified by OID4VCI Appendix E. The value represents the revocation state of the
     * Wallet Instance.
     */
    @SerialName("status")
    val status: JsonObject,

    /**
     * NumericDate specifying how long the Wallet Provider maintains revocation status at the referenced index.
     */
    @SerialName(JwtClaims.IanaRegistered.ClaimNames.RFC7519.EXP)
    @Serializable(with = InstantLongSerializer::class)
    val expiration: Instant,
)
