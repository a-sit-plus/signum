@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.awesn1.toBigInteger
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey.Companion.asPublicKey
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlin.time.Instant
import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlinx.serialization.decodeFromByteArray

private data class ExtraRepresentation(val serialNumber: Int)

private fun tbsCertificate(
    issuerUniqueID: ByteArray? = null,
    subjectUniqueID: ByteArray? = null,
) = TbsCertificate(
    serialNumber = BigInteger.ONE,
    signatureAlgorithm = EcdsaAlgorithm.withSHA256,
    issuerName = Name.EMPTY,
    subjectName = Name.EMPTY,
    validFrom = Instant.fromEpochSeconds(1_700_000_000),
    validUntil = Instant.fromEpochSeconds(1_800_000_000),
    publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    issuerUniqueID = issuerUniqueID,
    subjectUniqueID = subjectUniqueID,
    extensions = emptyList(),
)

val TbsCertificateEncodingTest by matrixSuite {
    "Unique IDs preserve ASN.1 bit order and trailing zero octets" {
        val issuerId = byteArrayOf(0x01, 0x80.toByte(), 0x00)
        val subjectId = byteArrayOf(0x80.toByte(), 0x01, 0x00)
        val source = tbsCertificate(issuerUniqueID = issuerId, subjectUniqueID = subjectId)
        val model = source.toAsn1()
        model.issuerUniqueID!!.bitCarryingBytes shouldBe issuerId
        model.subjectUniqueID!!.bitCarryingBytes shouldBe subjectId
        model.issuerUniqueID!!.numPaddingBits shouldBe 0
        model.subjectUniqueID!!.numPaddingBits shouldBe 0
        val decoded = TbsCertificate.fromAsn1(source.toAsn1.DER())
        decoded.issuerUniqueID shouldBe issuerId
        decoded.subjectUniqueID shouldBe subjectId
        decoded shouldBe source
    }

    "ASN.1 encoders and decoders retain the original model" {
        val source = tbsCertificate()
        source.realSourceRepresentation shouldBe null
        val value = source
        val bytes = value.toAsn1.DER()
        val decoded = TbsCertificate.fromAsn1(bytes)
        decoded.toAsn1.DER() shouldBe bytes
        decoded shouldBe source
        decoded.hashCode() shouldBe source.hashCode()
        val tlv = source.toAsn1.TLV()
        tlv.derEncoded shouldBe bytes
        TbsCertificate.fromAsn1(tlv) shouldBe source
        val buffer = Buffer()
        source.toAsn1.DER(buffer)
        buffer.peek().readByteArray() shouldBe bytes
        TbsCertificate.fromAsn1(buffer) shouldBe source
        shouldThrowAny { TbsCertificate.fromAsn1(Buffer().apply { write(bytes) }, limit = 1) }
        source.realSourceRepresentation shouldBe null
        decoded.toAsn1() shouldBeSameInstanceAs decoded.realSourceRepresentation
        val original = source.toAsn1()
        TbsCertificate.fromAsn1(original).toAsn1() shouldBeSameInstanceAs original
        shouldThrowAny { DER { maxInputLength = 1 }.decodeFromByteArray<X509TbsCertificate>(bytes) }
    }

    "A source from another format is not reused as X509" {
        val template = tbsCertificate()
        val foreignModel = ExtraRepresentation(2)
        val source = decodeFrom { _: ExtraRepresentation -> tbsCertificate() }(foreignModel)
        source.toAsn1() shouldBe template.toAsn1()
        source.realSourceRepresentation shouldBeSameInstanceAs foreignModel
        source shouldBe template
        source.hashCode() shouldBe template.hashCode()
        source.toAsn1.DER() shouldBe template.toAsn1.DER()
        source.realSourceRepresentation shouldBeSameInstanceAs foreignModel
    }

    "Unsupported original algorithms can round-trip without semantic decoding" {
        val template = tbsCertificate().toAsn1()
        val original = X509TbsCertificate(
            serialNumber = template.serialNumber,
            signatureAlgorithm = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null),
            issuerName = template.issuerName,
            validFrom = Asn1Time.SecondsCapped(template.validity.validFrom.instant),
            validUntil = Asn1Time.SecondsCapped(template.validity.validUntil.instant),
            subjectName = template.subjectName,
            subjectPublicKeyInfo = template.subjectPublicKeyInfo,
        )
        val bytes = Signum.Der.encodeToTlv(original).derEncoded
        val decoded = TbsCertificate.fromAsn1(bytes)
        decoded.toAsn1.DER() shouldBe bytes
        decoded.serialNumber shouldBe original.serialNumber.toBigInteger()
        decoded.validFrom shouldBe original.validity.validFrom.instant
        decoded.subjectName shouldBe Name.EMPTY
        decoded.publicKey shouldBe tbsCertificate().publicKey
        shouldThrowAny { decoded.signatureAlgorithm.preHashedSignatureFormat }
        decoded.toAsn1.DER() shouldBe bytes
    }

}
