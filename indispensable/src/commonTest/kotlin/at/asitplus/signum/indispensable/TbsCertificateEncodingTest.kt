@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1Time
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X509TbsCertificate
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.awesn1.toAsn1Integer
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
import kotlinx.serialization.encodeToByteArray

private data class ExtraRepresentation(val serialNumber: Int)

private fun tbsCertificate(
    issuerUniqueID: ByteArray? = null,
    subjectUniqueID: ByteArray? = null,
    serialNumber: BigInteger = BigInteger.ONE,
    extensions: List<CertificateExtension> = emptyList(),
) = TbsCertificate(
    serialNumber = serialNumber,
    signatureAlgorithm = EcdsaAlgorithm.withSHA256,
    issuerName = Name.EMPTY,
    subjectName = Name.EMPTY,
    validFrom = Instant.fromEpochSeconds(1_700_000_000),
    validUntil = Instant.fromEpochSeconds(1_800_000_000),
    publicKey = ECCurve.SECP_256_R_1.generator.asPublicKey(),
    issuerUniqueID = issuerUniqueID,
    subjectUniqueID = subjectUniqueID,
    extensions = extensions,
)

val TbsCertificateEncodingTest by matrixSuite {
    "Parsing tolerates serial-number profile violations while creation stays strict" {
        val template = tbsCertificate().asn1.toRepresentation()
        fun wire(serial: BigInteger, extensions: List<CertificateExtension> = emptyList()) = X509TbsCertificate(
            serialNumber = serial.toAsn1Integer(),
            signatureAlgorithm = template.signatureAlgorithm,
            issuerName = template.issuerName,
            validFrom = Asn1Time.SecondsCapped(template.validity.validFrom.instant),
            validUntil = Asn1Time.SecondsCapped(template.validity.validUntil.instant),
            subjectName = template.subjectName,
            subjectPublicKeyInfo = template.subjectPublicKeyInfo,
            extensions = extensions.map { it.asn1.toRepresentation() },
        )
        for (serial in listOf(BigInteger.ZERO, BigInteger(-1), BigInteger.ONE.shl(160))) {
            shouldThrowAny { tbsCertificate(serialNumber = serial) }
            val model = wire(serial)
            val bytes = Signum.Der.encodeToByteArray(model)
            val decoded = TbsCertificate.fromAsn1(bytes)
            decoded.serialNumber shouldBe serial
            decoded.asn1.toDer() shouldBe bytes
            TbsCertificate.fromAsn1(model).asn1.toRepresentation() shouldBeSameInstanceAs model
        }
        val validSerial = BigInteger.ONE.shl(158)
        tbsCertificate(serialNumber = validSerial).serialNumber shouldBe validSerial

        val extension = CertificateExtension(ObjectIdentifier("1.2.3.4"), value = byteArrayOf())
        val duplicates = listOf(extension, extension)
        shouldThrowAny { tbsCertificate(extensions = duplicates) }
        shouldThrowAny {
            TbsCertificate.fromAsn1(Signum.Der.encodeToByteArray(wire(BigInteger.ONE, duplicates)))
        }
    }

    "Unique IDs preserve ASN.1 bit order and trailing zero octets" {
        val issuerId = byteArrayOf(0x01, 0x80.toByte(), 0x00)
        val subjectId = byteArrayOf(0x80.toByte(), 0x01, 0x00)
        val source = tbsCertificate(issuerUniqueID = issuerId, subjectUniqueID = subjectId)
        val model = source.asn1.toRepresentation()
        model.issuerUniqueID!!.bitCarryingBytes shouldBe issuerId
        model.subjectUniqueID!!.bitCarryingBytes shouldBe subjectId
        model.issuerUniqueID!!.numPaddingBits shouldBe 0
        model.subjectUniqueID!!.numPaddingBits shouldBe 0
        val decoded = TbsCertificate.fromAsn1(source.asn1.toDer())
        decoded.issuerUniqueID shouldBe issuerId
        decoded.subjectUniqueID shouldBe subjectId
        decoded shouldBe source
    }

    "ASN.1 encoders and decoders retain the original model" {
        val source = tbsCertificate()
        source.realSourceRepresentation shouldBe null
        val value = source
        val bytes = value.asn1.toDer()
        val decoded = TbsCertificate.fromAsn1(bytes)
        decoded.asn1.toDer() shouldBe bytes
        decoded shouldBe source
        decoded.hashCode() shouldBe source.hashCode()
        val tlv = source.asn1.toTlv()
        tlv.derEncoded shouldBe bytes
        TbsCertificate.fromAsn1(tlv) shouldBe source
        val buffer = Buffer()
        source.asn1.toDer(buffer)
        buffer.peek().readByteArray() shouldBe bytes
        TbsCertificate.fromAsn1(buffer) shouldBe source
        shouldThrowAny { TbsCertificate.fromAsn1(Buffer().apply { write(bytes) }, limit = 1) }
        source.realSourceRepresentation shouldBe null
        decoded.asn1.toRepresentation() shouldBeSameInstanceAs decoded.realSourceRepresentation
        val original = source.asn1.toRepresentation()
        TbsCertificate.fromAsn1(original).asn1.toRepresentation() shouldBeSameInstanceAs original
        shouldThrowAny { DER { maxInputLength = 1 }.decodeFromByteArray<X509TbsCertificate>(bytes) }
    }

    "A source from another format is not reused as X509" {
        val template = tbsCertificate()
        val foreignModel = ExtraRepresentation(2)
        val source = decodeFrom { _: ExtraRepresentation -> tbsCertificate() }(foreignModel)
        source.asn1.toRepresentation() shouldBe template.asn1.toRepresentation()
        source.realSourceRepresentation shouldBeSameInstanceAs foreignModel
        source shouldBe template
        source.hashCode() shouldBe template.hashCode()
        source.asn1.toDer() shouldBe template.asn1.toDer()
        source.realSourceRepresentation shouldBeSameInstanceAs foreignModel
    }

    "Unsupported original algorithms can round-trip without semantic decoding" {
        val template = tbsCertificate().asn1.toRepresentation()
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
        decoded.asn1.toDer() shouldBe bytes
        decoded.serialNumber shouldBe original.serialNumber.toBigInteger()
        decoded.validFrom shouldBe original.validity.validFrom.instant
        decoded.subjectName shouldBe Name.EMPTY
        decoded.publicKey shouldBe tbsCertificate().publicKey
        shouldThrowAny { decoded.signatureAlgorithm.preHashedSignatureFormat }
        decoded.asn1.toDer() shouldBe bytes
    }

}
