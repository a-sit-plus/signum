package at.asitplus.signum.indispensable.pki
import at.asitplus.signum.indispensable.Encodable

import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.runRethrowing
import at.asitplus.awesn1.secondsCapped
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import kotlinx.serialization.Transient
import kotlin.time.Instant

/** The semantic certificate contents that are signed. Originals are retained separately. */
class TbsCertificate internal constructor(
    contentProvider: () -> ContentContainer,
    override val representations: Map<Encodable.Representation, Any>,
) : Encodable {
    private val content by lazy(contentProvider)
    private constructor(content: ContentContainer, representations: Map<Encodable.Representation, Any>) : this({ content }, representations)

    internal data class ContentContainer(
        val serialNumber: Asn1Integer,
        val signatureAlgorithm: SignatureAlgorithm,
        val issuerName: Name,
        val validFrom: Instant,
        val validUntil: Instant,
        val subjectName: Name,
        val publicKey: CryptoPublicKey,
        val issuerUniqueID: ByteArray?,
        val subjectUniqueID: ByteArray?,
        val extensions: List<CertificateExtension>,
    ) {

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ContentContainer) return false
            return serialNumber == other.serialNumber &&
                    signatureAlgorithm == other.signatureAlgorithm &&
                    issuerName == other.issuerName &&
                    validFrom == other.validFrom &&
                    validUntil == other.validUntil &&
                    subjectName == other.subjectName &&
                    publicKey == other.publicKey &&
                    issuerUniqueID.contentEquals(other.issuerUniqueID) &&
                    subjectUniqueID.contentEquals(other.subjectUniqueID) &&
                    extensions == other.extensions
        }

        override fun hashCode(): Int {
            var result = serialNumber.hashCode()
            result = 31 * result + signatureAlgorithm.hashCode()
            result = 31 * result + issuerName.hashCode()
            result = 31 * result + validFrom.hashCode()
            result = 31 * result + validUntil.hashCode()
            result = 31 * result + subjectName.hashCode()
            result = 31 * result + publicKey.hashCode()
            result = 31 * result + (issuerUniqueID?.contentHashCode() ?: 0)
            result = 31 * result + (subjectUniqueID?.contentHashCode() ?: 0)
            result = 31 * result + extensions.hashCode()
            return result
        }
    }

    constructor(
        serialNumber: Asn1Integer.Positive,
        signatureAlgorithm: SignatureAlgorithm,
        issuerName: Name,
        validFrom: Instant,
        validUntil: Instant,
        subjectName: Name,
        publicKey: CryptoPublicKey,
        issuerUniqueID: ByteArray? = null,
        subjectUniqueID: ByteArray? = null,
        extensions: List<CertificateExtension> = emptyList(),
    ) : this(
        ContentContainer(
            serialNumber = serialNumber,
            signatureAlgorithm = signatureAlgorithm,
            issuerName = issuerName,
            validFrom = validFrom.secondsCapped(),
            validUntil = validUntil.secondsCapped(),
            subjectName = subjectName,
            publicKey = publicKey,
            issuerUniqueID = issuerUniqueID,
            subjectUniqueID = subjectUniqueID,
            extensions = extensions,
        ), emptyMap()
    ) {
        runRethrowing { require(!serialNumber.isZero()) { "Serial Number must not be zero" } }
        validateExtensions(extensions)
    }
    val serialNumber: Asn1Integer get() = content.serialNumber

    val signatureAlgorithm: SignatureAlgorithm get() = content.signatureAlgorithm

    val issuerName: Name get() = content.issuerName

    val validFrom: Instant get() = content.validFrom

    val validUntil: Instant get() = content.validUntil

    val subjectName: Name get() = content.subjectName

    val issuerUniqueID: ByteArray? get() = content.issuerUniqueID

    val subjectUniqueID: ByteArray? get() = content.subjectUniqueID

    val extensions: List<CertificateExtension> get() = content.extensions

    val publicKey get() = content.publicKey

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions.
     */
    @Transient
    val subjectAlternativeNames: AlternativeNames? by lazy { extensions.findSubjectAltNames() }

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions.
     */
    @Transient
    val issuerAlternativeNames: AlternativeNames? by lazy { extensions.findIssuerAltNames() }

    override fun equals(other: Any?): Boolean = this === other || catchingUnwrapped {
        other is TbsCertificate && content == other.content
    }.getOrDefault(false)

    override fun hashCode(): Int = catchingUnwrapped { content.hashCode() }.getOrDefault(0)
    override fun toString(): String = catchingUnwrapped { "TbsCertificate($content)" }
        .getOrElse { "TbsCertificate(semantic content unavailable)" }

    companion object : Decodable<TbsCertificate>
}
