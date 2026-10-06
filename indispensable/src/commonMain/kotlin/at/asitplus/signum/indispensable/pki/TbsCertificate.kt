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
    val serialNumber: Asn1Integer,
    signatureAlgorithmProvider: () -> SignatureAlgorithm,
    val issuerName: Name,
    val validFrom: Instant,
    val validUntil: Instant,
    val subjectName: Name,
    publicKeyProvider: () -> CryptoPublicKey,
    val issuerUniqueID: ByteArray?,
    val subjectUniqueID: ByteArray?,
    val extensions: List<CertificateExtension>,
    override val representations: Map<Encodable.Representation, Any>,
) : Encodable {

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
        serialNumber,
        { signatureAlgorithm },
        issuerName,
        validFrom.secondsCapped(),
        validUntil.secondsCapped(),
        subjectName,
        { publicKey },
        issuerUniqueID,
        subjectUniqueID,
        extensions,
        emptyMap(),
    ) {
        runRethrowing { require(!serialNumber.isZero()) { "Serial Number must not be zero" } }
        validateExtensions(extensions)
    }

    val signatureAlgorithm: SignatureAlgorithm by lazy(signatureAlgorithmProvider)

    val publicKey: CryptoPublicKey by lazy(publicKeyProvider)

    /**
     * Contains `SubjectAlternativeName`s parsed from extensions.
     */
    @Transient
    // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
    val subjectAlternativeNames: AlternativeNames? by lazy { extensions.findSubjectAltNames() }

    /**
     * Contains `IssuerAlternativeName`s parsed from extensions.
     */
    @Transient
    // Nested conversion uses the application-wide DER configuration (docs/docs/default-der.md).
    val issuerAlternativeNames: AlternativeNames? by lazy { extensions.findIssuerAltNames() }

    private fun semanticEquals(other: TbsCertificate): Boolean {
        if (this === other) return true
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

    private fun semanticHashCode(): Int {
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

    override fun equals(other: Any?): Boolean = this === other || catchingUnwrapped {
        other is TbsCertificate && semanticEquals(other)
    }.getOrDefault(false)

    override fun hashCode(): Int = catchingUnwrapped { semanticHashCode() }.getOrDefault(0)
    override fun toString(): String = catchingUnwrapped {
        "TbsCertificate(serialNumber=$serialNumber, signatureAlgorithm=$signatureAlgorithm, " +
                "issuerName=$issuerName, validFrom=$validFrom, validUntil=$validUntil, " +
                "subjectName=$subjectName, publicKey=$publicKey, issuerUniqueID=$issuerUniqueID, " +
                "subjectUniqueID=$subjectUniqueID, extensions=$extensions)"
    }.getOrElse { "TbsCertificate(semantic content unavailable)" }

    companion object : Decodable<TbsCertificate>
}
