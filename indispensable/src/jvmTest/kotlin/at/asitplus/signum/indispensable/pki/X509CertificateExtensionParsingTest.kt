package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1EncapsulatingOctetString
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.Asn1.Bool
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.asn1.keyUsage
import at.asitplus.signum.indispensable.pki.pkiExtensions.AuthorityKeyIdentifierExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.KeyUsageExtension
import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.withDataSuites
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import org.bouncycastle.asn1.x509.KeyUsage
import de.infix.testBalloon.framework.core.TestConfig
import kotlin.time.Duration.Companion.minutes
import de.infix.testBalloon.framework.core.testScope
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.collections.shouldNotHaveSize
import io.kotest.matchers.shouldNotBe

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

    "valid authority key identifier" {
        val pem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIjCCAgqgAwIBAgIBAzANBgkqhkiG9w0BAQUFADApMQ0wCwYDVQQKDARQeUNB\n" +
                "MRgwFgYDVQQDDA9jcnlwdG9ncmFwaHkuaW8wHhcNMTUwNTAzMDk0OTU2WhcNMTYw\n" +
                "NTAyMDk0OTU2WjApMQ0wCwYDVQQKDARQeUNBMRgwFgYDVQQDDA9jcnlwdG9ncmFw\n" +
                "aHkuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCadi1UZioxdnP\n" +
                "ajqlRZHeKsSxvXXhgrWvlt91P3gV0dBThRFhJsLOhjNLz6PO6KeRbjz9GhTA2hdk\n" +
                "xtIpXrjvTv9dEJ1/k0xebsHWgFC43aTlgekw0U4cMwMe5NGeeg1tfzbJwldIN+cK\n" +
                "vabc08ADlkmM6DMnUArkzA2yii0DErRFMSIGrkDr6E9puord3h6Mh8Jfnc3TDAq8\n" +
                "Qo1DI2XM7oFSWNfecQ9KbIC5wzzT+7Shoyz7QmCk/XhRzt8Xcfc3yAXIwazvLf8b\n" +
                "YP1auaSG11a5E+w6onj91h8UHKKOXu+rdq5YYPZ+qUYpxA7ZJ/VAGadMulYbXaO8\n" +
                "Syi39HTpAgMBAAGjVTBTMFEGA1UdIwRKMEiAFDlFPso9Yh3qhkn2WqtAt6RwmPHs\n" +
                "oS2kKzApMQ0wCwYDVQQKDARQeUNBMRgwFgYDVQQDDA9jcnlwdG9ncmFwaHkuaW+C\n" +
                "AQMwDQYJKoZIhvcNAQEFBQADggEBAFbZYy6aZJUK/f7nJx2Rs/ht6hMbM32/RoXZ\n" +
                "JGbYapNVqVu/vymcfc/se3FHS5OVmPsnRlo/FIKDn/r5DGl73Sn/FvDJiLJZFucT\n" +
                "msyYuHZ+ZRYWzWmN2fcB3cfxj0s3qps6f5OoCOqoINOSe4HRGlw4X9keZSD+3xAt\n" +
                "vHNwQdlPC7zWbPdrzLT+FqR0e/O81vFJJS6drHJWqPcR3NQVtZw+UF7A/HKwbfeL\n" +
                "Nu2zj6165hzOi9HUxa2/mPr/eLUUV1sTzXp2+TFjt3rVCjW1XnpMLdwNBHzjpyAB\n" +
                "dTOX3iw0+BPy3s2jtnCW1PLpc74kvSTaBwhg74sq39EXfIKax00=\n" +
                "-----END CERTIFICATE-----"

        val cert = X509Certificate.decodeFromPem(pem).getOrThrow()

        val aki = cert.findExtension<AuthorityKeyIdentifierExtension>()
        aki shouldNotBe null
        aki?.keyIdentifier shouldNotBe null
        aki?.authorityCertIssuer?.size shouldNotBe 0
        aki?.authorityCertSerialNumber shouldNotBe null
    }

    "valid authority key identifier without keyIdentifier field" {
        val pem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDDDCCAfSgAwIBAgIBAzANBgkqhkiG9w0BAQUFADApMQ0wCwYDVQQKDARQeUNB\n" +
                "MRgwFgYDVQQDDA9jcnlwdG9ncmFwaHkuaW8wHhcNMTUwNTAzMTAxNTU2WhcNMTYw\n" +
                "NTAyMTAxNTU2WjApMQ0wCwYDVQQKDARQeUNBMRgwFgYDVQQDDA9jcnlwdG9ncmFw\n" +
                "aHkuaW8wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCadi1UZioxdnP\n" +
                "ajqlRZHeKsSxvXXhgrWvlt91P3gV0dBThRFhJsLOhjNLz6PO6KeRbjz9GhTA2hdk\n" +
                "xtIpXrjvTv9dEJ1/k0xebsHWgFC43aTlgekw0U4cMwMe5NGeeg1tfzbJwldIN+cK\n" +
                "vabc08ADlkmM6DMnUArkzA2yii0DErRFMSIGrkDr6E9puord3h6Mh8Jfnc3TDAq8\n" +
                "Qo1DI2XM7oFSWNfecQ9KbIC5wzzT+7Shoyz7QmCk/XhRzt8Xcfc3yAXIwazvLf8b\n" +
                "YP1auaSG11a5E+w6onj91h8UHKKOXu+rdq5YYPZ+qUYpxA7ZJ/VAGadMulYbXaO8\n" +
                "Syi39HTpAgMBAAGjPzA9MDsGA1UdIwQ0MDKhLaQrMCkxDTALBgNVBAoMBFB5Q0Ex\n" +
                "GDAWBgNVBAMMD2NyeXB0b2dyYXBoeS5pb4IBAzANBgkqhkiG9w0BAQUFAAOCAQEA\n" +
                "AViX0VIVQW2xyf0lfLiuFhrpdgX9i49StZvs+n/qH5yvWxfqRJAyVT1pk2Xs0Goj\n" +
                "ul7vYMfIGU0nIr8eLMlAH9j6lkllAd/oO1BDONZ1kH6PMdkOdvgz5gmhMQx6MFr6\n" +
                "zMzzQ+JOAnXKFFUEycOiRJyh3VXiTY1M1IG1kWY+LoqB72S7y9c25yFoHqUNi2Xf\n" +
                "rbuaR7gNS/4z7XvLJkbNbVS2+y69gQGL+8vk5AG7MiZ1mzUQ44r/zy6HNDBb55kK\n" +
                "H+YTYavijRApH5hccJBXyoIM0x9ZtKdcrV0h+J2KOFGEyHp3FXViFEB2IZUpJNA/\n" +
                "aduVbH8gZy5Y+cHzenwzBg==\n" +
                "-----END CERTIFICATE-----"
        val cert = X509Certificate.decodeFromPem(pem).getOrThrow()

        val aki = cert.findExtension<AuthorityKeyIdentifierExtension>()
        aki shouldNotBe null
        aki?.keyIdentifier shouldBe  null
        aki?.authorityCertIssuer?.size shouldNotBe 0
        aki?.authorityCertSerialNumber shouldNotBe null

    }
}