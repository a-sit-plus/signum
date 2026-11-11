@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrowAny
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

    override fun decodeFromAsn1(oid: ObjectIdentifier, value: Asn1Element): PolicyQualifierInfo? =
        if (oid == KnownOIDs.cps && value.tag == Asn1Element.Tag.STRING_UTF8)
            CpsUri(Asn1String.decodeFromTlv(value.asPrimitive()).value)
        else null

    override fun encodeToAsn1(value: CertificateExtension): X509CertificateExtension? = null
    override fun encodeToAsn1(generalName: GeneralName): X509GeneralName? = null
    override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? = null
    override fun encodeToAsn1(value: PolicyQualifierInfo): Asn1Element? = null
}

val LenientPkixProviderTest by matrixSuite {
    "A lower-priority provider recovers extensions rejected by built-in construction checks" {
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

    "A lower-priority provider recovers names rejected by the built-in parser" {
        val providers = ServiceLoader.load<GeneralNameFormatProvider>().toList()
        (providers.indexOf(PkixAsn1Provider) < providers.indexOf(LenientPkixProvider)) shouldBe true
        val source = X509GeneralName.Dns(" lenient.example ")
        shouldThrowAny { PkixAsn1Provider.decodeFromAsn1(source) }
        val recovered = GeneralName.fromAsn1(source).shouldBeInstanceOf<DNSName>()
        recovered.value shouldBe "lenient.example"
        (recovered.asn1.toRepresentation() as X509GeneralName.Dns).rawValue shouldBeSameInstanceAs source.rawValue
    }

    "OtherName providers recover inner OID failures without hiding the name family" {
        val source = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(
            MacAddressName.OID, Asn1OctetString(ByteArray(7) { 42 }),
        ))
        shouldThrowAny { BuiltinOtherNames.decodeFromAsn1(source) }
        val recovered = OtherName(source).shouldBeInstanceOf<MacAddressName>()
        recovered.address shouldBe ByteArray(6) { 42 }
        (recovered.asn1.toRepresentation() as X509GeneralName.Other).value shouldBeSameInstanceAs source.value
    }

    "Qualifier providers can accept UTF8 CPS URIs after the built-in IA5 decoder fails" {
        val qualifier = Asn1String.UTF8("https://lenient.example/policy").encodeToTlv()
        shouldThrowAny { BuiltinPolicyQualifiers.decodeFromAsn1(KnownOIDs.cps, qualifier) }
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
}
