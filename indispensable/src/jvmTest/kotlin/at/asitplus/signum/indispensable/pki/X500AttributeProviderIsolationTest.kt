@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.installIndispensable
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs

val X500AttributeProviderIsolationTest by matrixSuite {
    "Provider-only registration supplies aliases, canonical names, and typed text construction" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "providerAliases")
    }

    "Typed construction and lenient recovery work for both text and ASN.1 input" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "lenientRecovery")
    }

    "DN hex values use the ASN.1 provider for both an alias and a dotted OID" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "hexUsesAsn1Provider")
    }

    "A lenient DN provider can handle BER before the built-in fallback" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "lenientBer")
    }

    "Exhausted semantic providers preserve the original wire payload as unknown" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "exhaustedProviders")
    }

    "A text provider can render an opaque attribute with a non-ASN.1 source" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "opaqueText")
    }
}

internal object X500AttributeProviderScenarios {
    private fun registerNicknameProviders() {
        Signum.installIndispensable()
        for (provider in listOf(NicknameProvider("LEGACYNICK", strict = false), NicknameProvider("NICK", strict = true))) {
            ServiceLoader.register<AttributeTypeAndValueProvider>(provider)
            ServiceLoader.register<AttributeTypeAndValueAsn1Provider>(provider)
        }
    }

    @JvmStatic
    fun providerAliases() {
        registerNicknameProviders()
        val name = Name.fromString("nickname=alice")
        val attribute = name.relativeDistinguishedNames.single().attrsAndValues.single()
            .shouldBeInstanceOf<Nickname>()
        attribute.text shouldBe "alice"
        attribute.sourceFormat shouldBe "<no source>"
        name.toRfc2253String() shouldBe "NICK=alice"
    }

    @JvmStatic
    fun lenientRecovery() {
        registerNicknameProviders()
        for (text in listOf("alice", "ALICE")) {
            val semantic = AttributeTypeAndValue.fromString("NICK", text).shouldBeInstanceOf<Nickname>()
            semantic.text shouldBe "alice"
            val wire = Asn1String.Printable(text).encodeToTlv()
            val decoded = AttributeTypeAndValue.fromAsn1(
                X500AttributeTypeAndValue(Nickname.oid, wire))
                .shouldBeInstanceOf<Nickname>()
            decoded.text shouldBe "alice"
            decoded.asn1.toRepresentation().value shouldBe wire
        }
    }

    @JvmStatic
    fun hexUsesAsn1Provider() {
        Signum.installIndispensable()
        val oid = AttributeTypeAndValue.OID.commonName
        val source = X500AttributeTypeAndValue(oid, Asn1String.UTF8("Alice"))
        ServiceLoader.register<AttributeTypeAndValueAsn1Provider>(object : AttributeTypeAndValueAsn1Provider {
            override fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue? =
                if (value == source) TextAttributeTypeAndValue(oid, "ALICE") else null

            override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? = null
        })

        val fromModel = AttributeTypeAndValue.fromAsn1(source).shouldBeInstanceOf<TextAttributeTypeAndValue>()
        fromModel.text shouldBe "ALICE"
        val hex = source.value.derEncoded.toHexString()
        val fromHex = listOf("CN", oid.toString()).map { key ->
            AttributeTypeAndValue.fromString("$key=#$hex").shouldBeInstanceOf<TextAttributeTypeAndValue>()
                .also {
                    it.text shouldBe "ALICE"
                    it.sourceFormat shouldBe "X500AttributeTypeAndValue"
                    it.toRfc2253String() shouldBe "CN=ALICE"
                }
        }
        val opaqueDn = "1.2.3.4=#040101"
        AttributeTypeAndValue.fromString(opaqueDn).shouldBeInstanceOf<AttributeTypeAndValue.Unknown>()
            .sourceFormat shouldBe "X500AttributeTypeAndValue"
        Name.fromString(opaqueDn).toRfc2253String() shouldBe opaqueDn
        Signum.setDer(DER {})
        fromModel.asn1.toRepresentation() shouldBeSameInstanceAs source
        fromHex.forEach { it.asn1.toRepresentation() shouldBe source }
    }

    @JvmStatic
    fun lenientBer() {
        Signum.installIndispensable()
        val ber = "13810141" // PrintableString "A" with a BER long-form length.
        val dn = "CN=#$ber"
        shouldThrow<UnsupportedCryptoException> { AttributeTypeAndValue.fromString(dn) }

        ServiceLoader.register<AttributeTypeAndValueProvider>(object : AttributeTypeAndValueProvider {
            override fun decodeATV(key: AttributeTypeAndValueProvider.Key, value: AttributeTypeAndValueProvider.Value): AttributeTypeAndValue? {
                if (key != AttributeTypeAndValueProvider.Key("CN") || value !is AttributeTypeAndValueProvider.ByteArrayValue) return null
                value.bytes.toHexString() shouldBe ber
                return TextAttributeTypeAndValue(AttributeTypeAndValue.OID.commonName, "A")
            }

            override fun encodeATV(atv: AttributeTypeAndValue): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? = null
        })
        AttributeTypeAndValue.fromString(dn).toRfc2253String() shouldBe "CN=A"
    }

    @JvmStatic
    fun exhaustedProviders() {
        registerNicknameProviders()
        val wire = Asn1String.UTF8("").encodeToTlv()
        val value = AttributeTypeAndValue.fromAsn1(X500AttributeTypeAndValue(Nickname.oid, wire))
        value.shouldBeInstanceOf<ServiceLoader.UnknownShim>()
        value.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
        value.oid shouldBe Nickname.oid
        value.asn1.toRepresentation().value shouldBe wire
        AttributeTypeAndValue.fromAsn1(value.asn1.toDer()).asn1.toDer() shouldBe value.asn1.toDer()
    }

    @JvmStatic
    fun opaqueText() {
        Signum.installIndispensable()
        ServiceLoader.register<AttributeTypeAndValueProvider>(object : AttributeTypeAndValueProvider {
            override fun decodeATV(key: AttributeTypeAndValueProvider.Key, value: AttributeTypeAndValueProvider.Value) = null

            override fun encodeATV(atv: AttributeTypeAndValue): Pair<AttributeTypeAndValueProvider.Key, AttributeTypeAndValueProvider.Value>? {
                if (atv.oid != Nickname.oid) return null
                val text: String = atv.encodeTo { error("Expected the retained text") }
                return AttributeTypeAndValueProvider.Key("NICK") to AttributeTypeAndValueProvider.Value(text)
            }
        })

        val attribute = AttributeTypeAndValue.Unknown(Nickname.oid, "Alice", UnsupportedCryptoException("No semantic interpretation"))
        attribute.toRfc2253String() shouldBe "NICK=Alice"
    }
}
