@file:OptIn(at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.asn1
import at.asitplus.signum.indispensable.tag
import com.ionspin.kotlin.bignum.integer.BigInteger

import at.asitplus.awesn1.serialization.decodeFromTlv
import at.asitplus.awesn1.serialization.encodeToTlv

import at.asitplus.awesn1.Asn1EncapsulatingOctetString
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.encoding.Asn1.Bool
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
import at.asitplus.signum.indispensable.pki.extn.UsageBit
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

val X509CertificateExtensionParsingTest by matrixSuite {

    "valid keyUsage extension should parse as KeyUsageExtension" {
        val keyUsage = KeyUsage(UsageBit.DIGITAL_SIGNATURE)
        val ext = runCatching { CertificateExtension.fromAsn1((keyUsage).asn1.toTlv()) }.getOrNull()
        ext!!::class shouldBe KeyUsage::class
    }

    "Invalid keyUsage becomes Unknown with its decode failure retained" {
        val seq = Asn1.Sequence {
            +KnownOIDs.keyUsage
            +Bool(true)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = CertificateExtension.fromAsn1(seq)
            .shouldBeInstanceOf<CertificateExtension.Unknown>()
        ext.oid shouldBe KnownOIDs.keyUsage
        ext.critical shouldBe true
        ext.asn1.toRepresentation().value shouldBe byteArrayOf()
        ext.lookupResult.suppressedExceptions.isNotEmpty() shouldBe true
    }

    "Unknown extension remains an opaque representation carrier" {
        val seq = Asn1.Sequence {
            +ObjectIdentifier("1.2.3.4.5.6.7.8.9")
            +Bool(false)
            +Asn1EncapsulatingOctetString(listOf())
        }

        val ext = runCatching { CertificateExtension.fromAsn1(seq) }.getOrNull()
        ext!!.oid shouldBe ObjectIdentifier("1.2.3.4.5.6.7.8.9")
        ext.asn1.toRepresentation().value shouldBe byteArrayOf()
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

        val cert = Certificate.fromAsn1(pem)

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
        val cert = Certificate.fromAsn1(pem)

        val aki = cert.findExtension<AuthorityKeyIdentifier>()
        aki shouldNotBe null
        aki?.keyIdentifier shouldBe  null
        aki?.authorityCertIssuer?.size shouldNotBe 0
        aki?.authorityCertSerialNumber shouldNotBe null

    }

    // Programmatic construction: each public ctor must produce a valid extension that decodes back to the
    // same typed fields (build -> encodeToTlv -> CertificateExtension.decodeFromTlv -> typed again).

    "BasicConstraints constructed programmatically round-trips" {
        val decoded = CertificateExtension.fromAsn1((BasicConstraints(ca = true, pathLenConstraint = 3u)).asn1.toTlv()) as BasicConstraints
        decoded.ca shouldBe true
        decoded.pathLenConstraint shouldBe 3u

        // cA DEFAULT FALSE is omitted; a non-CA has no path length.
        val leaf = CertificateExtension.fromAsn1((BasicConstraints(ca = false)).asn1.toTlv()) as BasicConstraints
        leaf.ca shouldBe false
        leaf.pathLenConstraint shouldBe null
    }

    "PolicyConstraints constructed programmatically round-trips" {
        val decoded = CertificateExtension.fromAsn1((PolicyConstraints(requireExplicitPolicy = 0, inhibitPolicyMapping = 1)).asn1.toTlv()) as PolicyConstraints
        decoded.requireExplicitPolicy shouldBe 0
        decoded.inhibitPolicyMapping shouldBe 1

        // Both absent fields remain absent in the semantic model.
        val empty = CertificateExtension.fromAsn1((PolicyConstraints()).asn1.toTlv()) as PolicyConstraints
        empty.requireExplicitPolicy shouldBe null
        empty.inhibitPolicyMapping shouldBe null
    }

    "InhibitAnyPolicy constructed programmatically round-trips" {
        val decoded = CertificateExtension.fromAsn1((InhibitAnyPolicy(2)).asn1.toTlv()) as InhibitAnyPolicy
        decoded.skipCerts shouldBe 2
    }

    "SubjectKeyIdentifier constructed programmatically round-trips" {
        val keyId = byteArrayOf(1, 2, 3, 4, 5)
        val decoded = CertificateExtension.fromAsn1((SubjectKeyIdentifier(keyId)).asn1.toTlv()) as SubjectKeyIdentifier
        (decoded.keyIdentifier?.contentEquals(keyId)) shouldBe true
    }

    "ExtendedKeyUsage constructed programmatically round-trips" {
        val oids = setOf(ObjectIdentifier("1.3.6.1.5.5.7.3.1"), ObjectIdentifier("1.3.6.1.5.5.7.3.2"))
        val decoded = CertificateExtension.fromAsn1((ExtendedKeyUsage(oids)).asn1.toTlv()) as ExtendedKeyUsage
        decoded.keyUsages shouldBe oids
    }

    "AuthorityKeyIdentifier constructed programmatically round-trips" {
        val keyId = byteArrayOf(9, 8, 7, 6)
        val decoded = CertificateExtension.fromAsn1((AuthorityKeyIdentifier(keyIdentifier = keyId, authorityCertSerialNumber = com.ionspin.kotlin.bignum.integer.BigInteger(42))).asn1.toTlv()) as AuthorityKeyIdentifier
        (decoded.keyIdentifier?.contentEquals(keyId)) shouldBe true
        decoded.authorityCertSerialNumber shouldBe com.ionspin.kotlin.bignum.integer.BigInteger(42)
    }

    "NameConstraints constructed programmatically round-trips" {
        val permitted = GeneralSubtrees(mutableListOf(GeneralSubtree(DNSName(Asn1String.IA5("example.com")))))
        val decoded = CertificateExtension.fromAsn1((NameConstraints(permitted = permitted)).asn1.toTlv()) as NameConstraints
        decoded.permitted?.trees?.size shouldBe 1
        (decoded.permitted?.trees?.first()?.base as? GeneralName)?.tag shouldBe BigInteger.fromULong(X509GeneralName.Tags.dnsName.tagValue)
        decoded.excluded shouldBe null
    }

    "CertificatePolicies constructed programmatically round-trips" {
        val decoded = CertificateExtension.fromAsn1((CertificatePolicies(listOf(PolicyInformation(ObjectIdentifier("2.5.29.32.0"))))).asn1.toTlv()) as CertificatePolicies
        decoded.certificatePolicies.map { it.oid } shouldBe listOf(ObjectIdentifier("2.5.29.32.0"))
    }

    "PolicyMappings constructed programmatically round-trips" {
        val mapping = CertificatePolicyMap(
            ObjectIdentifier("2.16.840.1.101.3.2.1.48.1"),
            ObjectIdentifier("2.16.840.1.101.3.2.1.48.2"),
        )
        val decoded = CertificateExtension.fromAsn1((PolicyMappings(listOf(mapping))).asn1.toTlv()) as PolicyMappings
        decoded.policyMappings shouldBe listOf(mapping)
    }
}
