// --8<-- [start:pkix-supreme-opt-in]
@file:OptIn(at.asitplus.signum.indispensable.pki.ExperimentalPkiApi::class)
// --8<-- [end:pkix-supreme-opt-in]
package at.asitplus.signum.examples

import at.asitplus.awesn1.*
import at.asitplus.signum.Signum
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.signum.supreme.validate.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlin.time.Instant

val PkixSupremeExamples by matrixSuite {
    "binding CSR proof of possession and issuance" {
        // --8<-- [start:pkix-supreme-binding-csr]
        val client = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val backend = Signer.Ephemeral { ec { curve = ECCurve.SECP_256_R_1 } }
        val challengeOid = ObjectIdentifier("1.3.6.1.4.1.55555.1") /* (1)! */
        val challenge = byteArrayOf(1, 2, 3, 4)
        val subject = X500Name(RelativeDistinguishedName(CommonName("client")))
        val csr = client.sign(TbsCertificationRequest(subjectName = subject, publicKey = client.publicKey,
            attributes = listOf(CsrAttribute(challengeOid, Asn1OctetString(challenge)))))
        csr.verify() shouldBe SignatureVerifier.Success
        val receivedChallenge = csr.tbsCsr.attributes.single { it.oid == challengeOid }.value.single()
        receivedChallenge shouldBe Asn1OctetString(challenge)
        val certificate = backend.sign(TbsCertificate(serialNumber = Asn1Integer(1) as Asn1Integer.Positive,
            signatureAlgorithm = backend.signatureAlgorithm,
            issuerName = X500Name(RelativeDistinguishedName(CommonName("backend"))),
            validFrom = Instant.parse("2027-01-01T00:00:00Z"),
            validUntil = Instant.parse("2028-01-01T00:00:00Z"),
            subjectName = subject, publicKey = csr.tbsCsr.publicKey,
            extensions = listOf(KeyUsage(UsageBit.DIGITAL_SIGNATURE))))
        backend.makeVerifier().verify(certificate) shouldBe SignatureVerifier.Success
        certificate.tbsCertificate.publicKey shouldBe client.publicKey
        // --8<-- [end:pkix-supreme-binding-csr]
    }
    "fixed certificate path succeeds and expired path fails" {
        // --8<-- [start:pkix-supreme-validation]
        val root = Signum.Der.decodeFromPem<Certificate>(rootPem)
        val leaf = Signum.Der.decodeFromPem<Certificate>(leafPem)
        val context = CertificateValidationContext(
            trustAnchors = setOf(TrustAnchor.Certificate(root)), /* (1)! */
            date = Instant.parse("2024-01-01T00:00:00Z"))
        val chain: CertificateChain = listOf(leaf) /* (2)! */
        chain.buildPathAndValidate(context).isValid shouldBe true
        chain.buildPathAndValidate(context.copy(date = Instant.parse("3000-01-01T00:00:00Z"))).isValid shouldBe false
        // --8<-- [end:pkix-supreme-validation]
    }
}
// Fixed certificate fixtures from the repository’s Limbo test corpus: crl::certificate-not-on-crl.

private const val rootPem = """-----BEGIN CERTIFICATE-----
MIIBjzCCATWgAwIBAgIUIkTUg/UXr0eNPpyLBIpVlSnmf58wCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTcwMDEwMTAwMDAwMVoYDzI5
NjkwNTAzMDAwMDAxWjAaMRgwFgYDVQQDDA94NTA5LWxpbWJvLXJvb3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAT/UHNBjqS6eLqOCgYSY7cu6VBXSmCy6d0qr2L1
NWEUhd1ppzVfuJBvoijSwfxRAle90Ou2AwbQCaeI1CU0jBavo1cwVTAPBgNVHRMB
Af8EBTADAQH/MAsGA1UdDwQEAwIBBjAWBgNVHREEDzANggtleGFtcGxlLmNvbTAd
BgNVHQ4EFgQUu8VnD+0SKwhz8PckzmPII3lyoS8wCgYIKoZIzj0EAwIDSAAwRQIg
Daf5C72MTw7VP4t8B20CjDNs15dg6mj+bZZo0H/fZNgCIQDiYomrgrh1oqA4CobS
64WEWjDfO8Dtj0dZmdPFk5m9Yw==
-----END CERTIFICATE-----
"""
private const val leafPem = """-----BEGIN CERTIFICATE-----
MIIBsDCCAVagAwIBAgIUXGrPUvdctNf8+6P3SCgweAohuiAwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPeDUwOS1saW1iby1yb290MCAXDTcwMDEwMTAwMDAwMVoYDzI5
NjkwNTAzMDAwMDAxWjAWMRQwEgYDVQQDDAtleGFtcGxlLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABNZnE9Irjuav63gEQ1QI+G03wLVNA9fwwSP+t5aOrFNH
ACzoo47jeyiaDLRz+f8xiO8wrFp+0eTCgUHxEtGjZu+jfDB6MB0GA1UdDgQWBBTe
So+AjDBEex7Ouw+d9zYoaWpR4TAfBgNVHSMEGDAWgBS7xWcP7RIrCHPw9yTOY8gj
eXKhLzALBgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAwEwFgYDVR0RBA8w
DYILZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIgZRmEoVDE7AgWNpiJwB2o
JrLPllstGufcvG31fK8CRCYCIQC9MJyusIPnp2oevZ0QIpwOrgFIc0A+lfCDLWVm
Hlp3CA==
-----END CERTIFICATE-----
"""
