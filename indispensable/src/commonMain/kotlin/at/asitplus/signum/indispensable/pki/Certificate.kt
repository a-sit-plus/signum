package at.asitplus.signum.indispensable.pki

import at.asitplus.KmmResult
import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.io.Base64Strict
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable(with = TbsCertificate.Companion::class)
data class TbsCertificate
@Throws(Asn1Exception::class)
constructor(
    override val backing: X509TbsCertificate
) : Awesn1Backed<X509TbsCertificate> {

    constructor(
        version: Int? = 3,
        serialNumber: Asn1Integer,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validFrom: Asn1Time,
        validUntil: Asn1Time,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        X509TbsCertificate(
            version = version,
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm.toAlgorithmIdentifier(),
            issuerName = issuerName.map { it.backing },
            validFrom = validFrom,
            validUntil = validUntil,
            subjectName = subjectName.map { it.backing },
            subjectPublicKeyInfo = publicKey.toSubjectPublicKeyInfo(),
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
        )
    )

    constructor(
        version: Int? = 3,
        serialNumber: Asn1Integer,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        issuerName: List<RelativeDistinguishedName>,
        validity: Validity,
        subjectName: List<RelativeDistinguishedName>,
        publicKey: CryptoPublicKey,
        issuerUniqueID: Asn1BitString? = null,
        subjectUniqueID: Asn1BitString? = null,
        extensions: List<X509CertificateExtension>? = null,
    ) : this(
        version,
        serialNumber,
        signatureAlgorithm,
        issuerName,
        validity.validFrom,
        validity.validUntil,
        subjectName,
        publicKey,
        issuerUniqueID,
        subjectUniqueID,
        extensions,
    )

    val extensions: List<X509CertificateExtension>? by lazy { backing.extensions?.value }

    val version get() = backing.version
    val rawVersion get() = backing.rawVersion?.value
    val serialNumber get() = backing.serialNumber
    val issuerName get() = backing.issuerName
    val subjectName get() = backing.subjectName
    val validity get() = backing.validity
    val subjectUniqueID get() = backing.subjectUniqueID
    val issuerUniqueID get() = backing.issuerUniqueID

    val validFrom get() = validity.validFrom
    val validUntil get() = validity.validUntil

    init {
        //do we want to be this strict?
        extensions?.let { require(it.isNotEmpty()) { "Extensions is empty" } }
        if (extensions?.distinctBy { it.oid }?.size != extensions?.size) throw Asn1StructuralException("Multiple extensions with the same OID found")
    }

    val decodedPublicKey by lazy {
        catching {
            CryptoPublicKey.fromSubjectPublicKeyInfo(backing.subjectPublicKeyInfo)
        }
    }

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val subjectAlternativeNames: GeneralNames? = extensions?.findSubjectAltNames()

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions. This property is initialized right away.
     * This incurs *some* structural validation, but still allows for contents violating
     * [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280), e.g. all UTF-8 strings are accepted, even though
     * this is too lenient.
     */
    @Transient
    val issuerAlternativeNames: GeneralNames? = extensions?.findIssuerAltNames()


    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "TbsCertificate(${DER.encodeToByteArray(backing).encodeToString(Base64Strict)})"
    }

    companion object :
        Awesn1BackedSerializer<X509TbsCertificate, TbsCertificate>(X509TbsCertificate.serializer(), ::TbsCertificate)
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable(with = Certificate.Companion::class)
data class Certificate(
    override val backing: X509Certificate
) : Awesn1Backed<X509Certificate>, Asn1PemEncodable<Asn1Sequence> {

    override val pemLabel: String
        get() = "CERTIFICATE"

    @Throws(IllegalArgumentException::class)
    constructor(
        tbsCertificate: TbsCertificate,
        signatureAlgorithm: X509SignatureAlgorithmDescription,
        signature: CryptoSignature,
    ) : this(
        X509Certificate(
            tbsCertificate.backing,
            signatureAlgorithm.toAlgorithmIdentifier(),
            signature.backing
        )
    )

    override fun encodeToTlv(): Asn1Sequence = DER.encodeToTlv(backing) as Asn1Sequence

    @get:Throws(Asn1Exception::class)
    val tbsCertificate: TbsCertificate by lazy { TbsCertificate(backing.tbsCertificate) }

    @get:Throws(Asn1Exception::class)
    val signatureAlgorithm: X509SignatureAlgorithmDescription =
        X509SignatureAlgorithmDescription.fromAlgorithmIdentifier(backing.tbsCertificate.signatureAlgorithm)


    /**
     * Debug String representation. Uses Base64 encoded DER representation
     */
    override fun toString(): String {
        return "X509Certificate(${DER.encodeToByteArray(backing)?.encodeToString(Base64Strict)})"
    }

    val decodedPublicKey get() = tbsCertificate.decodedPublicKey

    val decodedSignature: KmmResult<CryptoSignature> by lazy {
        catching {
            signatureAlgorithm.requireSupported()
            CryptoSignature.fromSignatureValue(backing.signatureValue)
        }
    }


    companion object :
        Awesn1BackedSerializer<X509Certificate, Certificate>(X509Certificate.serializer(), ::Certificate),
        Asn1PemDecodable<Asn1Sequence, Certificate> {

        override val pemLabel: String get() = "CERTIFICATE"
        /* private object EB_STRINGS {
             const val DEFAULT = "CERTIFICATE"
             const val LEGACY = "TRUSTED CERTIFICATE"
         }*/

        /**
         * Tries to decode [src] into an [Certificate], by parsing the bytes directly as ASN.1 structure,
         * or by decoding from Base64, or by decoding to a String, stripping PEM headers
         * (`-----BEGIN CERTIFICATE-----`) and then decoding from Base64.
         */
        fun decodeFromByteArray(src: ByteArray): Certificate? = catchingUnwrapped {
            DER.decodeFromByteArray<Certificate>(src)
        }.getOrNull() ?: catchingUnwrapped {
            DER.decodeFromByteArray<Certificate>(src.decodeToByteArray(Base64()))
        }.getOrNull() ?: Certificate.decodeFromPem(src.decodeToString())

        override fun doDecode(src: Asn1Sequence): Certificate =
            DER.decodeFromTlv(this, src)

    }
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()
