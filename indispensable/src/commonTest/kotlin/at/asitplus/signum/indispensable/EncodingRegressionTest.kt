package at.asitplus.signum.indispensable

import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.Asn1Sequence
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.awesn1.crypto.pki.X500RelativeDistinguishedName
import at.asitplus.awesn1.crypto.pki.X500Name
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe
import io.kotest.assertions.throwables.shouldThrow

val EncodingRegressionTest by matrixSuite {
    "iOS EC public key encoding is uncompressed regardless of compression preference" {
        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1).publicKey

        key.iosEncoded shouldBe key.toAnsiX963Encoded(useCompressed = false)
    }

    "RDN decoding preserves an opaque non-string attribute value" - {
        listOf(
            "OCTET STRING" to Asn1OctetString(byteArrayOf(1)),
            "SEQUENCE" to Asn1Sequence(listOf(Asn1OctetString(byteArrayOf(1)))),
        ).asData(nameFn = { it.first }) - { (_, value) ->
            val original = X500RelativeDistinguishedName(setOf(
                X500AttributeTypeAndValue(ObjectIdentifier("1.2.3.4"), value),
            ))

            test("Model and DER decoding preserve the value without claiming to validate it") {
                val decoded = RelativeDistinguishedName.fromAsn1(original)
                decoded.attrsAndValues.single().isValid shouldBe null
                decoded.asn1.toRepresentation() shouldBe original
                RelativeDistinguishedName.fromAsn1(decoded.asn1.toDer()) shouldBe decoded
            }
            test("An enclosing Name also preserves the opaque value") {
                val name = X500Name(listOf(original))
                val decoded = Name.fromAsn1(name)
                decoded.asn1.toRepresentation() shouldBe name
                Name.fromAsn1(decoded.asn1.toDer()) shouldBe decoded
            }
        }
    }

    "RDN validation still rejects invalid attributes" - {
        listOf(
            "Non-string common name" to X500AttributeTypeAndValue(
                AttributeTypeAndValue.Descriptor.OID.commonName, Asn1OctetString(byteArrayOf(1))),
            "Malformed string with unknown OID" to X500AttributeTypeAndValue(
                ObjectIdentifier("1.2.3.4"), Asn1Element.parse(byteArrayOf(0x16, 0x01, 0x80.toByte()))),
        ).asData(nameFn = { it.first }) - { (_, attribute) ->
            test("Invalid values fail validation and decoding") {
                AttributeTypeAndValue.fromAsn1(attribute).isValid shouldBe false
                shouldThrow<Asn1Exception> {
                    RelativeDistinguishedName.fromAsn1(X500RelativeDistinguishedName(setOf(attribute)))
                }
            }
        }
    }

    "Unknown signature algorithms, digests and MACs are distinct values" {
        val original = X509AlgorithmIdentifier(ObjectIdentifier("1.2.3.4"), null)

        setOf<Any>(
            SignatureAlgorithm.fromAsn1(original),
            Digest.fromAsn1(original),
            MessageAuthenticationCode.fromAsn1(original),
        ).size shouldBe 3
    }
}
