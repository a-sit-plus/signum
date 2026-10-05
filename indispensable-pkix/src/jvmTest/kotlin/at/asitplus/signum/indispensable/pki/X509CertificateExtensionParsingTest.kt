package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.Bool
import at.asitplus.awesn1.encoding.decodeFromAsn1ContentBytes
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.keyUsage
import at.asitplus.signum.indispensable.pki.extn.AuthorityKeyIdentifier
import at.asitplus.signum.indispensable.pki.extn.BasicConstraints
import at.asitplus.signum.indispensable.pki.extn.CertificatePolicies
import at.asitplus.signum.indispensable.pki.extn.CertificatePolicyMap
import at.asitplus.signum.indispensable.pki.extn.ExtendedKeyUsage
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtree
import at.asitplus.signum.indispensable.pki.extn.GeneralSubtrees
import at.asitplus.signum.indispensable.pki.extn.InhibitAnyPolicy
import at.asitplus.signum.indispensable.pki.extn.KeyUsage
import at.asitplus.signum.indispensable.pki.extn.NameConstraints
import at.asitplus.signum.indispensable.pki.extn.PolicyConstraints
import at.asitplus.signum.indispensable.pki.extn.PolicyInformation
import at.asitplus.signum.indispensable.pki.extn.PolicyMappings
import at.asitplus.signum.indispensable.pki.extn.SubjectKeyIdentifier
import at.asitplus.signum.indispensable.pki.x500.DNSName
import at.asitplus.testballoon.matrix.matrixSuite
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.decodeFromTlv
import at.asitplus.signum.indispensable.encodeToTlv
import at.asitplus.signum.indispensable.pki.extn.UsageBit
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val X509CertificateExtensionParsingTest by matrixSuite {
    SignumPkix.install()

    "valid keyUsage extension should parse as KeyUsageExtension" {
        val keyUsage = KeyUsage(UsageBit.DIGITAL_SIGNATURE)
        val ext = runCatching { CertificateExtension.decodeFromTlv(keyUsage.encodeToTlv()) }.getOrNull()
        ext!!::class shouldBe KeyUsage::class
    }

    "invalid keyUsage extension should parse as InvalidCertificateExtension" {
        val seq = Asn1.Sequence {
            +KnownOIDs.keyUsage
            +Bool(true)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = runCatching { CertificateExtension.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), seq) }.getOrNull()
        ext!!::class shouldBe X509CertificateExtension::class
    }

    "unknown extension should parse as X509CertificateExtension" {
        val seq = Asn1.Sequence {
            +ObjectIdentifier("1.2.3.4.5.6.7.8.9")
            +Bool(false)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = runCatching { CertificateExtension.decodeFromTlv(Awesn1X509CertificateExtension.serializer(), seq) }.getOrNull()
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

        val cert = Certificate.decodeFromPem(pem)

        val aki = cert.findExtension<AuthorityKeyIdentifier>()
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
        val cert = Certificate.decodeFromPem(pem)

        val aki = cert.findExtension<AuthorityKeyIdentifier>()
        aki shouldNotBe null
        aki?.keyIdentifier shouldBe  null
        aki?.authorityCertIssuer?.size shouldNotBe 0
        aki?.authorityCertSerialNumber shouldNotBe null

    }

    // Programmatic construction: each public ctor must produce a valid extension that decodes back to the
    // same typed fields (build -> encodeToTlv -> CertificateExtension.decodeFromTlv -> typed again).

    "BasicConstraints constructed programmatically round-trips" {
        val decoded = CertificateExtension.decodeFromTlv(
            BasicConstraints(ca = true, pathLenConstraint = 3u).encodeToTlv()
        ) as BasicConstraints
        decoded.ca shouldBe true
        decoded.pathLenConstraint shouldBe 3u

        // cA DEFAULT FALSE is omitted; a non-CA has no path length.
        val leaf = CertificateExtension.decodeFromTlv(BasicConstraints(ca = false).encodeToTlv()) as BasicConstraints
        leaf.ca shouldBe false
        leaf.pathLenConstraint shouldBe null
    }

    "PolicyConstraints constructed programmatically round-trips" {
        val decoded = CertificateExtension.decodeFromTlv(
            PolicyConstraints(requireExplicitPolicy = 0, inhibitPolicyMapping = 1).encodeToTlv()
        ) as PolicyConstraints
        decoded.requireExplicitPolicy shouldBe Asn1Integer(0)
        decoded.inhibitPolicyMapping shouldBe Asn1Integer(1)

        // both absent -> the -1 sentinel
        val empty = CertificateExtension.decodeFromTlv(PolicyConstraints().encodeToTlv()) as PolicyConstraints
        empty.requireExplicitPolicy shouldBe Asn1Integer.fromDecimalString("-1")
        empty.inhibitPolicyMapping shouldBe Asn1Integer.fromDecimalString("-1")
    }

    "InhibitAnyPolicy constructed programmatically round-trips" {
        val decoded = CertificateExtension.decodeFromTlv(InhibitAnyPolicy(2).encodeToTlv()) as InhibitAnyPolicy
        decoded.skipCerts shouldBe 2
    }

    "SubjectKeyIdentifier constructed programmatically round-trips" {
        val keyId = byteArrayOf(1, 2, 3, 4, 5)
        val decoded = CertificateExtension.decodeFromTlv(SubjectKeyIdentifier(keyId).encodeToTlv()) as SubjectKeyIdentifier
        (decoded.keyIdentifier?.contentEquals(keyId)) shouldBe true
    }

    "ExtendedKeyUsage constructed programmatically round-trips" {
        val oids = setOf(ObjectIdentifier("1.3.6.1.5.5.7.3.1"), ObjectIdentifier("1.3.6.1.5.5.7.3.2"))
        val decoded = CertificateExtension.decodeFromTlv(ExtendedKeyUsage(oids).encodeToTlv()) as ExtendedKeyUsage
        decoded.keyUsages shouldBe oids
    }

    "AuthorityKeyIdentifier constructed programmatically round-trips" {
        val keyId = byteArrayOf(9, 8, 7, 6)
        val decoded = CertificateExtension.decodeFromTlv(
            AuthorityKeyIdentifier(keyIdentifier = keyId, authorityCertSerialNumber = Asn1Integer(42)).encodeToTlv()
        ) as AuthorityKeyIdentifier
        (decoded.keyIdentifier?.contentEquals(keyId)) shouldBe true
        decoded.authorityCertSerialNumber?.let { Asn1Integer.decodeFromAsn1ContentBytes(it) } shouldBe Asn1Integer(42)
    }

    "NameConstraints constructed programmatically round-trips" {
        val permitted = GeneralSubtrees(mutableListOf(GeneralSubtree(DNSName(Asn1String.IA5("example.com")))))
        val decoded = CertificateExtension.decodeFromTlv(
            NameConstraints(permitted = permitted).encodeToTlv()
        ) as NameConstraints
        decoded.permitted?.trees?.size shouldBe 1
        (decoded.permitted?.trees?.first()?.base as? GeneralName.X509Representable)?.tag shouldBe X509GeneralName.Tags.dnsName
        decoded.excluded shouldBe null
    }

    "CertificatePolicies constructed programmatically round-trips" {
        val decoded = CertificateExtension.decodeFromTlv(
            CertificatePolicies(listOf(PolicyInformation(ObjectIdentifier("2.5.29.32.0")))).encodeToTlv()
        ) as CertificatePolicies
        decoded.certificatePolicies.map { it.oid } shouldBe listOf(ObjectIdentifier("2.5.29.32.0"))
    }

    "PolicyMappings constructed programmatically round-trips" {
        val mapping = CertificatePolicyMap(
            ObjectIdentifier("2.16.840.1.101.3.2.1.48.1"),
            ObjectIdentifier("2.16.840.1.101.3.2.1.48.2"),
        )
        val decoded = CertificateExtension.decodeFromTlv(
            PolicyMappings(listOf(mapping)).encodeToTlv()
        ) as PolicyMappings
        decoded.policyMappings shouldBe listOf(mapping)
    }
}