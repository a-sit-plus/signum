package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.WithSourceRepresentation
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findIssuerAltNames
import at.asitplus.signum.indispensable.pki.AlternativeNames.Companion.findSubjectAltNames
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.Transient
import kotlin.time.Instant

/** The semantic certificate contents that are signed. Originals are retained separately. */
class TbsCertificate(
    val serialNumber: BigInteger,
    val signatureAlgorithm: SignatureAlgorithm,
    val issuerName: Name,
    validFrom: Instant,
    validUntil: Instant,
    val subjectName: Name,
    val publicKey: CryptoPublicKey,
    val issuerUniqueID: ByteArray? = null,
    val subjectUniqueID: ByteArray? = null,
    val extensions: List<CertificateExtension> = emptyList(),
    strict: Boolean = true
) : WithSourceRepresentation {
    override val sourceRepresentation = SourceRepresentationStorage()

    init {
        if (strict) {
            serialNumber.encodeToAsn1ContentBytes().size.let { size ->
                runRethrowing { require(size <= 20) { "Serial Number too long for X.509. Limit = 20 value octets, is: $size" } }
            }
            runRethrowing { require(serialNumber.isPositive) { "Serial Number must be positive" } }
            if (!extensions.allDistinctByOids()) {
                throw Asn1StructuralException("Multiple extensions with the same OID found")
            }
        }
    }

    val validFrom = validFrom.secondsCapped()
    val validUntil = validUntil.secondsCapped()

    /** Contains `SubjectAlternativeName`s parsed from extensions. */
    @Transient
    // Nested conversion uses the application-wide DER configuration (docs/docs/extensibility.md).
    val subjectAlternativeNames: AlternativeNames? by lazy { extensions.findSubjectAltNames() }

    /** Contains `IssuerAlternativeName`s parsed from extensions. */
    @Transient
    // Nested conversion uses the application-wide DER configuration (docs/docs/extensibility.md).
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

    companion object
}
