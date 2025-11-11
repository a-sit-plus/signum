package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.keyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.x509.KeyUsage
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope

val X509CertificateExtensionParsingTest by testSuite {

    "valid keyUsage extension should parse as KeyUsageExtension" {
        val keyUsage = KeyUsage(KeyUsage.digitalSignature)
        val seq = Asn1.Sequence {
            +KnownOIDs.keyUsage
            +Bool(true)
            +Asn1EncapsulatingOctetString(listOf(Asn1Element.parse(keyUsage.encoded)))
        }
        val ext = runCatching { X509CertificateExtension.decodeFromTlv(seq) }.getOrNull()
        ext!!::class shouldBe KeyUsageExtension::class
    }

    "invalid keyUsage extension should parse as InvalidCertificateExtension" {
        val seq = Asn1.Sequence {
            +KnownOIDs.keyUsage
            +Bool(true)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = runCatching { X509CertificateExtension.decodeFromTlv(seq) }.getOrNull()
        ext!!::class shouldBe X509CertificateExtension.InvalidCertificateExtension::class
    }

    "unknown extension should parse as X509CertificateExtension" {
        val seq = Asn1.Sequence {
            +ObjectIdentifier("1.2.3.4.5.6.7.8.9")
            +Bool(false)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = runCatching { X509CertificateExtension.decodeFromTlv(seq) }.getOrNull()
        ext!!::class shouldBe X509CertificateExtension::class
    }
}