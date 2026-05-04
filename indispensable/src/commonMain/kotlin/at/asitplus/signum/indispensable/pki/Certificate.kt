package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1PemDecodable
import at.asitplus.awesn1.Asn1PemEncodable
import at.asitplus.awesn1.Asn1Primitive
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1StructuralException
import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findIssuerAltNames
import at.asitplus.awesn1.crypto.pki.GeneralNames.Companion.findSubjectAltNames
import at.asitplus.awesn1.decodeFromPem
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.DER
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.io.Base64Strict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Transient
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.encodeToByteArray
import kotlin.collections.asSequence
import kotlin.sequences.asSequence
import kotlin.text.asSequence

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
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
            signature.toSignatureValue()
        )
    )

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

    val decodedSignature: CryptoSignature by lazy {
        catching {
            signatureAlgorithm.requireSupported()
            CryptoSignature.Companion.fromX509Encoded(signatureAlgorithm, rawSignature)
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
           D(Asn1Element.parse(src) as Asn1Sequence)
        }.getOrNull() ?: catchingUnwrapped {
            Certificate.decodeFromTlv(Asn1Element.parse(src.decodeToByteArray(Base64())) as Asn1Sequence)
        }.getOrNull() ?: Certificate.decodeFromPem(src.decodeToString()).getOrNull()
    }
}

typealias CertificateChain = List<Certificate>

val CertificateChain.leaf: Certificate get() = first()
val CertificateChain.root: Certificate get() = last()

private
/** De-/serializes Base64 strings to/from [ByteArray] */
object Asn1BitStringSerializer : TransformingSerializerTemplate<Asn1BitString?, String>(
    parent = String.serializer(),
    encodeAs = {
        if (it == null) "" else byteArrayOf(
            it.numPaddingBits,
            *it.rawBytes
        ).encodeToString(Base64Strict)
    },
    decodeAs = {
        if (it == "") null
        else Asn1BitString.decodeFromTlv(
            Asn1Primitive(
                Asn1Element.Tag.BIT_STRING,
                it.decodeToByteArray(Base64Strict)
            )
        )
    }
)