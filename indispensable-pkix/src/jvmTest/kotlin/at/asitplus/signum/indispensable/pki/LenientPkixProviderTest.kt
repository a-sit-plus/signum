@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.signum.test.isolatedScenario
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.kotest.matchers.types.shouldBeSameInstanceAs
import kotlinx.serialization.builtins.ListSerializer

/** Test-only recovery for deliberately narrow fixtures, registered below the built-in providers. */
internal object LenientPkixProvider : CertificateExtensionProvider, GeneralNameFormatProvider,
    OtherNameAsn1Provider, PolicyQualifierAsn1Provider {
    override fun decodeFromAsn1(asn1: X509CertificateExtension): CertificateExtension? =
        if (asn1.oid == BasicConstraints.oid && asn1.value.contentEquals("300302012a".hexToByteArray()))
            BasicConstraints(ca = false, critical = asn1.critical) // Ignore an inappropriate pathLenConstraint.
        else null

    override fun decodeFromAsn1(generalName: X509GeneralName): GeneralName? =
        if (generalName is X509GeneralName.Dns && generalName.value == " lenient.example ")
            DNSName(generalName.value.trim())
        else null

    override fun decodeFromAsn1(value: X509GeneralName.Other): OtherName? {
        val raw = value.value as? X509GeneralName.Other.SemanticValue.Generic ?: return null
        if (raw.oid != MacAddressName.OID) return null
        val address = raw.value.asPrimitive().content
        return if (address.contentEquals(ByteArray(7) { 42 })) MacAddressName(address.copyOf(6)) else null
    }

    override fun decodeFromAsn1(value: Asn1PolicyQualifier): PolicyQualifierInfo? =
        if (value.oid == KnownOIDs.cps && value.qualifier.tag == Asn1Element.Tag.STRING_UTF8)
            CpsUri(Asn1String.decodeFromTlv(value.qualifier.asPrimitive()).value)
        else null

    override fun encodeToAsn1(value: CertificateExtension): X509CertificateExtension? = null
    override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = null
    override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? = null
    override fun encodeToAsn1(value: PolicyQualifierInfo): Asn1PolicyQualifier? =
        if (value is MismatchedPolicyQualifier)
            Asn1PolicyQualifier(KnownOIDs.unotice, Asn1String.UTF8("mismatched").encodeToTlv())
        else null
}

private class MismatchedPolicyQualifier : PolicyQualifierInfo {
    override val oid = KnownOIDs.cps
    override val sourceRepresentation = SourceRepresentationStorage()
}

val LenientPkixProviderTest by matrixSuite {
    "A lower-priority provider recovers extensions rejected by built-in construction checks" {
        isolatedScenario(LenientPkixScenarios::class.java, "extensions")
    }
    "A lower-priority provider recovers names rejected by the built-in parser" {
        isolatedScenario(LenientPkixScenarios::class.java, "names")
    }
    "OtherName providers recover inner OID failures without hiding the name family" {
        isolatedScenario(LenientPkixScenarios::class.java, "otherNames")
    }
    "OtherName dispatch visits general and specialized providers once in precedence order" {
        isolatedScenario(LenientPkixScenarios::class.java, "otherNamePrecedence")
    }
    "Typed OtherName preserves the opaque source and diagnostic before PKIX installation" {
        isolatedScenario(LenientPkixScenarios::class.java, "otherNameBeforeInstall")
    }
    "Qualifier providers can accept UTF8 CPS URIs after the built-in IA5 decoder fails" {
        isolatedScenario(LenientPkixScenarios::class.java, "qualifiers")
    }
    "Qualifier encoding rejects providers that change the OID" {
        isolatedScenario(LenientPkixScenarios::class.java, "mismatchedQualifierOid")
    }
}

internal object LenientPkixScenarios {
    @JvmStatic
    fun extensions() {
        ServiceLoader.register<CertificateExtensionProvider>(LenientPkixProvider)
        Signum.installPkix()
        val providers = ServiceLoader.load<CertificateExtensionProvider>().toList()
        (providers.indexOf(PkixAsn1Provider) < providers.indexOf(LenientPkixProvider)) shouldBe true
        val source = X509CertificateExtension(BasicConstraints.oid, true, "300302012a".hexToByteArray())
        shouldThrowAny { PkixAsn1Provider.decodeFromAsn1(source) }
        val recovered = CertificateExtension.fromAsn1(source).shouldBeInstanceOf<BasicConstraints>()
        recovered.ca shouldBe false
        recovered.pathLenConstraint shouldBe null
        recovered.critical shouldBe true
        recovered.asn1.toRepresentation() shouldBeSameInstanceAs source
    }

    @JvmStatic
    fun names() {
        ServiceLoader.register<GeneralNameFormatProvider>(LenientPkixProvider)
        Signum.installPkix()
        val providers = ServiceLoader.load<GeneralNameFormatProvider>().toList()
        (providers.indexOf(PkixAsn1Provider) < providers.indexOf(LenientPkixProvider)) shouldBe true
        val source = X509GeneralName.Dns(" lenient.example ")
        shouldThrowAny { PkixAsn1Provider.decodeFromAsn1(source) }
        val recovered = GeneralName.fromAsn1(source).shouldBeInstanceOf<DNSName>()
        recovered.value shouldBe "lenient.example"
        (recovered.asn1.toRepresentation() as X509GeneralName.Dns).rawValue shouldBeSameInstanceAs source.rawValue
    }

    @JvmStatic
    fun otherNames() {
        ServiceLoader.register<OtherNameAsn1Provider>(LenientPkixProvider)
        Signum.installPkix()
        val source = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            MacAddressName.OID, Asn1OctetString(ByteArray(7) { 42 }),
        ))
        shouldThrowAny { BuiltinOtherNames.decodeFromAsn1(source) }
        val recovered = OtherName(source).shouldBeInstanceOf<MacAddressName>()
        recovered.address shouldBe ByteArray(6) { 42 }
        (recovered.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs source.value
    }

    @JvmStatic
    fun otherNamePrecedence() {
        val calls = mutableListOf<String>()
        var success: String? = null
        val failures = listOf("high", "specialized", "low").associateWith { UnsupportedCryptoException(it) }
        fun general(label: String) = object : GeneralNameFormatProvider {
            override fun decodeFromAsn1(generalName: X509GeneralName): GeneralName? {
                calls += label
                if (success == label) return DNSName("$label.example")
                if (success == null) throw failures.getValue(label)
                return null
            }
            override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = null
        }
        fun specialized(label: String) = object : OtherNameAsn1Provider {
            override fun decodeFromAsn1(value: X509GeneralName.Other): OtherName? {
                calls += label
                if (success == label) return SmtpUtf8Mailbox("test@example.com")
                if (success == null && label == "specialized") throw failures.getValue(label)
                return null
            }
            override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? = null
        }

        ServiceLoader.register<GeneralNameFormatProvider>(general("low"))
        Signum.installPkix()
        ServiceLoader.register<OtherNameAsn1Provider>(specialized("last"))
        ServiceLoader.register<OtherNameAsn1Provider>(specialized("specialized"))
        ServiceLoader.register<GeneralNameFormatProvider>(general("high"))
        val source = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            ObjectIdentifier("1.2.3.99"), Asn1OctetString(byteArrayOf(1)),
        ))

        success = "high"
        shouldThrow<UnsupportedCryptoException> { OtherName(source) }.message shouldBe
                "Expected OtherName for OID ${source.value.oid}, received DNSName"
        calls.toList() shouldBe listOf("high")

        calls.clear()
        success = "specialized"
        OtherName(source).shouldBeInstanceOf<SmtpUtf8Mailbox>()
        calls.toList() shouldBe listOf("high", "specialized")

        calls.clear()
        success = "low"
        GeneralName.fromAsn1(source).shouldBeInstanceOf<DNSName>().value shouldBe "low.example"
        calls.toList() shouldBe listOf("high", "specialized", "last", "low")

        calls.clear()
        success = null
        val opaque = GeneralName.fromAsn1(source).shouldBeInstanceOf<OtherName.Unknown>()
        calls.toList() shouldBe listOf("high", "specialized", "last", "low")
        val before = opaque.lookupResult.suppressedExceptions
        before.first() shouldBeSameInstanceAs failures.getValue("high")
        before[1].suppressedExceptions.single() shouldBeSameInstanceAs failures.getValue("specialized")
        before.last() shouldBeSameInstanceAs failures.getValue("low")
        (opaque.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs source.value

        calls.clear()
        val boxedSource: X509GeneralName = source
        val direct = PkixAsn1Provider.decodeFromAsn1(boxedSource).shouldBeInstanceOf<OtherName.Unknown>()
        calls.toList() shouldBe listOf("specialized", "last")
        direct.lookupResult.suppressedExceptions.single() shouldBeSameInstanceAs failures.getValue("specialized")
        direct.asn1.toRepresentation() shouldBeSameInstanceAs boxedSource
        (PkixAsn1Provider.encodeToAsn1(direct) as X509GeneralName.Other).value shouldBeSameInstanceAs source.value
    }

    @JvmStatic
    fun otherNameBeforeInstall() {
        val source = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            ObjectIdentifier("1.2.3.99"), Asn1OctetString(byteArrayOf(1)),
        ))
        val generic = GeneralName.fromAsn1(source).shouldBeInstanceOf<GeneralName.Unknown>()
        val initialOpaque = OtherName(source).shouldBeInstanceOf<OtherName.Unknown>()
        initialOpaque.lookupResult.message shouldBe generic.lookupResult.message
        initialOpaque.oid shouldBe source.value.oid

        ServiceLoader.register<GeneralNameFormatProvider>(object : GeneralNameFormatProvider {
            override fun decodeFromAsn1(generalName: X509GeneralName) = generic
            override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = null
        })
        val opaque = OtherName(source).shouldBeInstanceOf<OtherName.Unknown>()
        opaque.lookupResult shouldBeSameInstanceAs generic.lookupResult
        (opaque.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs source.value
    }

    @JvmStatic
    fun qualifiers() {
        ServiceLoader.register<PolicyQualifierAsn1Provider>(LenientPkixProvider)
        Signum.installPkix()
        val qualifier = Asn1String.UTF8("https://lenient.example/policy").encodeToTlv()
        shouldThrowAny { BuiltinPolicyQualifiers.decodeFromAsn1(Asn1PolicyQualifier(KnownOIDs.cps, qualifier)) }
        val body = Signum.Der.encodeToByteArray(ListSerializer(FallbackPolicyWire.serializer()), listOf(
            FallbackPolicyWire(ObjectIdentifier("1.2.3.4"), listOf(FallbackQualifierWire(KnownOIDs.cps, qualifier))),
        ))
        val policies = CertificateExtension.fromAsn1(X509CertificateExtension(CertificatePolicies.oid, false, body))
            .shouldBeInstanceOf<CertificatePolicies>()
        policies.certificatePolicies.single().policyQualifiers.single().shouldBeInstanceOf<CpsUri>()
            .uri.toString() shouldBe "https://lenient.example/policy"
        // Rebuilding the extension exercises the qualifier's retained wire representation.
        CertificatePolicies(policies.certificatePolicies).asn1.toRepresentation().value shouldBe body
    }

    @JvmStatic
    fun mismatchedQualifierOid() {
        ServiceLoader.register<PolicyQualifierAsn1Provider>(LenientPkixProvider)
        Signum.installPkix()
        val failure = shouldThrow<Asn1Exception> {
            encodeCertificatePolicies(listOf(PolicyInformation(ObjectIdentifier("1.2.3.4"), listOf(MismatchedPolicyQualifier()))))
        }
        failure.cause.shouldBeInstanceOf<UnsupportedCryptoException>().suppressedExceptions.single()
            .shouldBeInstanceOf<IllegalStateException>().message shouldBe
            "Encoded policy qualifier OID ${KnownOIDs.unotice} does not match ${KnownOIDs.cps}"
    }
}
