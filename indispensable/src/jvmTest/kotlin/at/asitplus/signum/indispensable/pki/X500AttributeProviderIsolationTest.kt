@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.sourceFormat
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

val X500AttributeProviderIsolationTest by matrixSuite {
    "Text lookup allows provider registration after DER initialization" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "registrationAfterTextLookup")
    }

    "Provider-only registration supplies aliases, canonical names, and typed text construction" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "providerAliases")
    }

    "Typed construction and lenient recovery work for both text and ASN.1 input" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "lenientRecovery")
    }

    "Exhausted semantic providers preserve the original wire payload as unknown" {
        isolatedScenario(X500AttributeProviderScenarios::class.java, "exhaustedProviders")
    }
}

internal object X500AttributeProviderScenarios {
    private fun registerNicknameProviders() {
        Signum.Der
        ServiceLoader.register<AttributeTypeAndValueProvider>(LenientNicknameProvider)
        ServiceLoader.register<AttributeTypeAndValueProvider>(NicknameProvider)
    }

    @JvmStatic
    fun registrationAfterTextLookup() {
        Signum.Der
        // Text lookup does not seal provider registration or couple it to the DER lifecycle.
        AttributeTypeAndValue.oidForName("CN") shouldBe AttributeTypeAndValue.OID.commonName
        registerNicknameProviders()
        AttributeTypeAndValue.oidForName("NICK") shouldBe Nickname.oid
    }

    @JvmStatic
    fun providerAliases() {
        registerNicknameProviders()
        val name = Name.fromString("nickname=alice")
        val attribute = name.relativeDistinguishedNames.single().attrsAndValues.single()
            .shouldBeInstanceOf<Nickname>()
        attribute.text shouldBe "alice"
        attribute.sourceFormat shouldBe "<no source>"
        AttributeTypeAndValue.oidForName("NiCk") shouldBe Nickname.oid
        AttributeTypeAndValue.nameForOid(Nickname.oid) shouldBe "NICK"
        name.toRfc2253String() shouldBe "nick=alice"
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
}
