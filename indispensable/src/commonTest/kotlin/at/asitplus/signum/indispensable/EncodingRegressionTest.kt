@file:OptIn(at.asitplus.signum.SignumInternals::class)

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
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValueAsn1Provider
import at.asitplus.signum.indispensable.pki.AttributeAsn1Provider
import at.asitplus.signum.indispensable.pki.TextAttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.Name
import at.asitplus.signum.indispensable.sign.EcdsaPrivateKey
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import at.asitplus.testballoon.matrix.matrixSuite
import com.ionspin.kotlin.bignum.integer.BigInteger
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.kotest.assertions.throwables.shouldThrow

val EncodingRegressionTest by matrixSuite {
    "iOS EC public key encoding is uncompressed regardless of compression preference" {
        val key = EcdsaPrivateKey.WithPublicKey(BigInteger.ONE, ECCurve.SECP_256_R_1).publicKey

        key.iosEncoded shouldBe key.toAnsiX963Encoded(useCompressed = false)
    }

    "Unrecognized non-string ATVs round-trip through RDNs and Names" - {
        listOf(
            "OCTET STRING" to Asn1OctetString(byteArrayOf(1)),
            "SEQUENCE" to Asn1Sequence(listOf(Asn1OctetString(byteArrayOf(1)))),
        ).asData(nameFn = { it.first }) - { (_, value) ->
            val attribute = X500AttributeTypeAndValue(ObjectIdentifier("1.2.3.4"), value)
            val original = X500RelativeDistinguishedName(setOf(attribute))

            test("Unknown fallback preserves the OID, payload and original DER") {
                val bytes = Signum.Der.encodeToTlv(original).derEncoded
                val decoded = RelativeDistinguishedName.fromAsn1(bytes)
                val atv = decoded.attrsAndValues.single()
                atv.shouldBeInstanceOf<ServiceLoader.UnknownShim>().lookupResult.suppressedExceptions shouldBe emptyList()
                atv.oid shouldBe attribute.oid
                atv.asn1.toRepresentation().value shouldBe value
                decoded.asn1.toDer() shouldBe bytes
                RelativeDistinguishedName.fromAsn1(original) shouldBe decoded
            }
            test("An enclosing Name preserves the unknown attribute without semantic rejection") {
                val model = X500Name(listOf(original))
                val bytes = Signum.Der.encodeToTlv(model).derEncoded
                val decoded = Name.fromAsn1(bytes)
                val atv = decoded.relativeDistinguishedNames.single().attrsAndValues.single()
                atv.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
                atv.oid shouldBe attribute.oid
                atv.asn1.toRepresentation().value shouldBe value
                decoded.asn1.toDer() shouldBe bytes
            }
        }
    }

    "Failed interpretation preserves malformed ATVs without rejecting the containing name" - {
        data class Case(val name: String, val attribute: X500AttributeTypeAndValue, val decoderFailed: Boolean)
        val malformedString = Asn1Element.parse(byteArrayOf(0x16, 0x01, 0x80.toByte()))
        listOf(
            Case("Non-string common name", X500AttributeTypeAndValue(
                AttributeTypeAndValue.OID.commonName, Asn1OctetString(byteArrayOf(1))), true),
            Case("Malformed known string", X500AttributeTypeAndValue(
                AttributeTypeAndValue.OID.commonName, malformedString), true),
            Case("Malformed string with unknown OID", X500AttributeTypeAndValue(
                ObjectIdentifier("1.2.3.4"), malformedString), false),
        ).asData(nameFn = { it.name }) - { case ->
            test("Known decoding failures and unsupported OIDs retain distinct lookup diagnostics") {
                val decoded = AttributeTypeAndValue.fromAsn1(case.attribute)
                val fallback = decoded.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
                fallback.lookupResult.suppressedExceptions.isNotEmpty() shouldBe case.decoderFailed
                decoded.oid shouldBe case.attribute.oid
                decoded.asn1.toRepresentation() shouldBeSameInstanceAs case.attribute
                val bytes = decoded.asn1.toDer()
                val reparsed = AttributeTypeAndValue.fromAsn1(bytes)
                reparsed.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
                reparsed.asn1.toDer() shouldBe bytes
            }
            test("RDN and Name decoding retain the malformed payload byte for byte") {
                val rdn = X500RelativeDistinguishedName(setOf(case.attribute))
                val model = X500Name(listOf(rdn))
                val bytes = Signum.Der.encodeToTlv(model).derEncoded
                val decoded = Name.fromAsn1(bytes)
                val atv = decoded.relativeDistinguishedNames.single().attrsAndValues.single()
                atv.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
                atv.asn1.toRepresentation().value shouldBe case.attribute.value
                decoded.asn1.toDer() shouldBe bytes
                RelativeDistinguishedName.fromAsn1(rdn).attrsAndValues.single() shouldBe atv
            }
        }
    }

    "A later ATV provider can recover a payload rejected by the built-in decoder" {
        val source = X500AttributeTypeAndValue(
            AttributeTypeAndValue.OID.commonName, Asn1OctetString("Alice".encodeToByteArray()),
        )
        val lenient = object : AttributeTypeAndValueAsn1Provider {
            override fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue? =
                if (value.oid == source.oid && value.value is Asn1OctetString)
                    TextAttributeTypeAndValue(value.oid, value.value.asPrimitive().content.decodeToString())
                else null
            override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? = null
        }
        // Keep provider order local so concurrent tests cannot affect each other's decoders.
        val providers = ServiceLoader.ServiceProviders("ATV", listOf(AttributeAsn1Provider, lenient))
        val recovered = decodeFrom<X500AttributeTypeAndValue, AttributeTypeAndValue> {
            providers.get(it, AttributeTypeAndValueAsn1Provider::decodeFromAsn1)
        }(source).shouldBeInstanceOf<TextAttributeTypeAndValue>()
        recovered.text shouldBe "Alice"
        recovered.asn1.toRepresentation() shouldBeSameInstanceAs source
    }

    "RDN construction still rejects empty sets and duplicate OIDs" {
        shouldThrow<Asn1Exception> { RelativeDistinguishedName(emptySet()) }
        val oid = AttributeTypeAndValue.OID.commonName
        val first = TextAttributeTypeAndValue(oid, "Alice")
        val second = TextAttributeTypeAndValue(oid, "Bob")
        shouldThrow<Asn1Exception> { RelativeDistinguishedName(setOf(first, second)) }
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
