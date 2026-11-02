package at.asitplus.signum.supreme.validate

import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

@OptIn(ExperimentalPkiApi::class)
val PkixDerRegressionTest by matrixSuite {
    SignumPkix.install()

    val validationDate = Instant.parse("2027-01-01T00:00:00Z")
    fun certificate(name: String): Certificate = Certificate.decodeFromPem(PkixDerFixtures.pem(name))
    suspend fun validate(
        root: String,
        vararg pathFromLeaf: String,
        policies: Set<ObjectIdentifier> = emptySet(),
        expectedEku: Set<ObjectIdentifier> = emptySet(),
    ): CertificateValidationResult = pathFromLeaf.map(::certificate).buildPathAndValidate(
        CertificateValidationContext(
            date = validationDate,
            trustAnchors = setOf(TrustAnchor.Certificate(certificate(root))),
            explicitPolicyRequired = policies.isNotEmpty(),
            initialPolicies = policies,
            expectedEku = expectedEku,
        )
    )

    suspend fun expectValid(
        root: String,
        vararg pathFromLeaf: String,
        policies: Set<ObjectIdentifier> = emptySet(),
        expectedEku: Set<ObjectIdentifier> = emptySet(),
    ) {
        validate(root, *pathFromLeaf, policies = policies, expectedEku = expectedEku)
            .shouldBeInstanceOf<CertificateValidationResult.Success>()
    }
    "valid end-entity certificate may omit SKI" {
        expectValid("root", "no-ski")
    }

    // RFC 5280 6.1 treats the anchor as input; but a certificate-backed anchor is subject to CA
    // checks like any path cert. Use TrustAnchor.PublicKey for BC-less legacy roots instead.
    "a BC-less legacy root must not validate as a certificate anchor" {
        val trustStore = setOf(TrustAnchor.Certificate(certificate("legacy-root")))
        val result = listOf(certificate("legacy-leaf")).buildPathAndValidate(
            CertificateValidationContext(date = validationDate, trustAnchors = trustStore)
        )
        result.shouldBeInstanceOf<CertificateValidationResult.BuildPathFailure>()
        result.chainFailures.values.flatMap { it.validatorFailures }
            .any { it.validator is BasicConstraintsValidator } shouldBe true
    }

    // The same BC-less root, modeled as a public-key anchor, validates fine:
    // issuer-name match plus signature verification is all a key anchor requires.
    "a BC-less legacy root still validates as a public-key anchor" {
        val legacyRoot = certificate("legacy-root")
        val trustStore = setOf(TrustAnchor.PublicKey(legacyRoot.publicKey, legacyRoot.tbsCertificate.subjectName))
        val result = listOf(certificate("legacy-leaf")).buildPathAndValidate(
            CertificateValidationContext(date = validationDate, trustAnchors = trustStore)
        )
        result.shouldBeInstanceOf<CertificateValidationResult.Success>()
    }
    "an intermediate CA without keyUsage can still sign certificates" {
        // RFC 5280 6.1.4(n): keyCertSign is checked only if the extension is present.
        expectValid("ku-root", "ku-leaf", "ku-absent-ca")
    }

    "a clientAuth-only intermediate must not issue a serverAuth path" {
        // The intermediate has critical EKU=clientAuth; the leaf has EKU=serverAuth.
        val serverAuth = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
        val result = validate(
            "ku-root", "server-leaf", "client-auth-ca",
            expectedEku = setOf(serverAuth),
        )
        result.shouldBeInstanceOf<CertificateValidationResult.BuildPathFailure>()
        result.chainFailures.values.flatMap { it.validatorFailures }
            .any { it.validator is KeyUsageValidator } shouldBe true
    }

    "expectedEku requires the requested usage to be present on the leaf" {
        // no-ski has no EKU extension (also checks the missing-extension case).
        val serverAuth = ObjectIdentifier("1.3.6.1.5.5.7.3.1")
        val result = validate("root", "no-ski", expectedEku = setOf(serverAuth))
        result.shouldBeInstanceOf<CertificateValidationResult.BuildPathFailure>()
        result.chainFailures.values.flatMap { it.validatorFailures }
            .any { it.validator is KeyUsageValidator } shouldBe true
    }

    "DNS name constraints must not interpret a non-DNS subject CN as a DNS SAN" {
        // CN=Alice, no DNS SAN; the intermediate permits only DNS:example.com.
        expectValid("root", "cn-leaf", "cn-intermediate")
    }

    "explicit policy succeeds when a leaf contains requested OID and anyPolicy" {
        val policy = ObjectIdentifier("1.2.3.4")
        expectValid("root", "policy-leaf", policies = setOf(policy))
    }

    "validation must not narrow a reused trust anchor's name constraints" {
        val trustAnchor = TrustAnchor.Certificate(certificate("constrained-root"))
        val context = CertificateValidationContext(
            date = validationDate,
            trustAnchors = setOf(trustAnchor),
        )

        // step 1: root -> intermediate 2 -> leaf 2 validates
        listOf(certificate("second-leaf"), certificate("plain-intermediate"))
            .buildPathAndValidate(context)
            .shouldBeInstanceOf<CertificateValidationResult.Success>()

        // step 2, root -> intermediate 1 (narrowed) -> leaf 1 validates
        listOf(certificate("first-leaf"), certificate("narrowed-intermediate"))
            .buildPathAndValidate(context)
            .shouldBeInstanceOf<CertificateValidationResult.Success>()

        // step 3: root -> intermediate 2 -> leaf 2 must still validate!
        listOf(certificate("second-leaf"), certificate("plain-intermediate"))
            .buildPathAndValidate(context)
            .shouldBeInstanceOf<CertificateValidationResult.Success>()
    }
}

/** Embedded PEM to make the tests commonTest-friendly without platform-specific resource loading. */
private object PkixDerFixtures {
    private val pems = mapOf(
        "root" to """
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUYCKV5eRT7CIegnCWv1/JSACkeqUwDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQUEtJWCBSZXZpZXcgUm9vdDAeFw0yNjEwMzAxMzU4Mzha
Fw0zNjEwMjcxMzU4MzhaMBsxGTAXBgNVBAMMEFBLSVggUmV2aWV3IFJvb3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCxlU4SmA2ZjMvaouFKI+18hXYo
HL5LBVHMKbNFrulNFb/eMhKsADC+7IxO/d4FKuBU+yY1ieIwRdxbm/ab4G6bMAQt
6CG4yFTHiJW3oguCBqwWxZux1/soJan3kPJjqnPSYmaAdaMH/+q5gj1uymOxpQ0S
eBNlo4cu057Uc3JRZsCPGiqHENPOu503IyaMdAGXWn1hTtnIZq1+LOF7tEQgSP34
47QaYEPQqwJS2g1na3GBnJJQU3Q3cngC+tuCtsVHkiXg9SrRpPs5FDRjpTi6XYXb
Ij8TTmQwFqKRQjgeQADTVPrQKFwSwCCD9URAwiPM8qZgmwrrIsoSXuhhAGn3AgMB
AAGjRTBDMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMB0GA1Ud
DgQWBBTYmh+n1yMhIm6gXfhe70OcgK6SvTANBgkqhkiG9w0BAQsFAAOCAQEAT6SF
K5wlb3WQ9hIUJT4eHCKSz9RByNiIITxUw9brZAr1LxC/oFSBn5QVjHzX8IPJK+Qo
Q29S6SpbSTFQAjaqjhOUDMiMdAygVAQlS9xPHD/1bnSDe1zsP/7ZnCQARm29Q4GX
MeoAMlRlKGsYaED8ozg4dJMyP3FJjv9D7ShSu6NxL0p9PO6jRuqIyuePuYH93Qkn
baYhv80Bhj6/JKqEapHN4ehkyGliB3lQwpqT/WmcLjRFN6NMfAwlDjM7AVJc/q8G
FENZGRRmD5luPH7d+7Fw/5Q3Nn4iwR0ifqnsi49fsZbVIqPPrRmuItUytt3nn3jM
CPBR0YR76MSdtI+zyA==
-----END CERTIFICATE-----
""".trimIndent(),
        "legacy-root" to """
-----BEGIN CERTIFICATE-----
MIIDATCCAemgAwIBAgIUWJIUfSEHw7zpkB2QhyAyb2aR9nQwDQYJKoZIhvcNAQEL
BQAwITEfMB0GA1UEAwwWTGVnYWN5IFJvb3QgV2l0aG91dCBCQzAeFw0yNjEwMzAx
MzU4MzhaFw0zNjEwMjcxMzU4MzhaMCExHzAdBgNVBAMMFkxlZ2FjeSBSb290IFdp
dGhvdXQgQkMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCpXJC/FyRi
CNaLLjXlJVqVi5tCk5gmgGqw7vkPqTLHqRJ2KeGFs2strdj07+faZrwhrCP4E36Y
lCFH1ruItBdJDMr9NRHlsItX4hte+fnGkRindcEzwv7XafDkJoFPusaNK3Gtijum
87Sb6fjtzXO3M2zqHyWz+/COKrec6IvrA/IA5GkHZMGx9YNleDbHUKWGpZtWScTG
TquhlUjJiKvbL42VWzkLQPRn9VEVEm5MhmW7Gcu/OaMHUK34S5OgxF6LzlgXEWL1
r11oo4w9iaLp/xPOp9qbkgj59SjBOGaJZJah7F4v+lpGgkWUendnlEbPLRgL2y4c
0Mh34+1A4tsZAgMBAAGjMTAvMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUZbOc
gbFcNfmk575JMCFnB52KRD8wDQYJKoZIhvcNAQELBQADggEBAEj9iR1Hh/ZAT9tx
/ecBBHQGwxm+XoIHmRCwYUETTSyG27UuwX5SS1hP5Kr6tQjCEPVse0u7O4Rx55WL
v07g47aggQ/3kqInTx/Ypvtc8qjyTw0b/6tPZSnOemsBGwI76TOC6GGooAyarw2M
vjaRYv1KcCSSmtVNGf1lvuApghQbrB6N/+KwAf12+hx0My+F737a+Ja7z1OONxOS
/NvOfg8AJ2Px6SelKRt5fFRuGrruLcOaNUxBWO6f5SiJI9rHFHyq3fWKZlhiyj4K
me286JpFlRElYgj6Sf5+YxrGr4BJYffCl9CW5Ampk2n0X3NFIO5a1q28cKuUL5UM
XTMxIjA=
-----END CERTIFICATE-----
""".trimIndent(),
        "constrained-root" to """
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUeRsT6R0if2GgLRWYIQllpm/3620wDQYJKoZIhvcNAQEL
BQAwIzEhMB8GA1UEAwwYQ29uc3RyYWluZWQgVHJ1c3QgQW5jaG9yMB4XDTI2MTAz
MDEzNTgzOFoXDTM2MTAyNzEzNTgzOFowIzEhMB8GA1UEAwwYQ29uc3RyYWluZWQg
VHJ1c3QgQW5jaG9yMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwk6n
8p9+g+u9Lztke5VhFjIZmIA+WGD9/Pg+A25NX3EEtA5RuesNv2bFLt9cqQz1KTFn
NoQhsUiPSeZlxAxRPok4GIWWMh6lxpfWvkBng3eEtkl4aT7tMMWm2rJr37xA/6Gj
Aui8FL6RMxDdWCR7w7zSQJbZ3LMQQN47QoRMccwd3nQkSeA4znMeBLBf+VMb6sDt
/v+zpB9TBrJVkZ32wxClYlvdHLueBUAfVinYC33qUDEe4XOAC+sYnURO4rYDEzI9
JesbZyX8SJ3oAvac7KYsArzbhgviflctDk3s4rT8tWEPIa2x1ReCv9x23BeMWjdf
8gisyt2nDrqwFH8nfwIDAQABo2QwYjASBgNVHRMBAf8ECDAGAQH/AgEDMA4GA1Ud
DwEB/wQEAwIBBjAdBgNVHQ4EFgQUSI7QaZk89PIAsi+6KgtURg28H84wHQYDVR0e
AQH/BBMwEaAPMA2CC2V4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQBJ4Flv
VWM9xEjmm7ySvZHr2kW6pwYkN/6pLbif5uIgMsIKE8cSZU1PQ8uoxoPUFdIP9rWP
4vqbsDRg33R0ccKhDx5bRtIKRXBykrCZxNYWIBN7ue2oaEQK0WixNuE7/mc0CmAC
jLHHkKBho/EiD4YrZCkF2ctjOih8mfx1cSdmeC6DeEmN+nuAFhiX8NJ95Z+8jGIa
rHpTV487zzfsLN475BdxhOyyaLoWH848HC1YM+B4us6vgYxuH/weJDYFAkbLrlOW
mIabPzzgYIs/d6sbepP0nqigAiajA/2FA0xWf5eFrqLkbEZQyCv0f4iecDKfPgZJ
B1OD0d93wvf85pGz
-----END CERTIFICATE-----
""".trimIndent(),
        "no-ski" to """
-----BEGIN CERTIFICATE-----
MIIC7jCCAdagAwIBAgICA+kwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQUEtJ
WCBSZXZpZXcgUm9vdDAeFw0yNjEwMzAxMzU4MzhaFw0zNjEwMjcxMzU4MzhaMBYx
FDASBgNVBAMMC05vIFNLSSBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAuTpfNcIPqcGd4631OcQakoSthx0cxxBr4Kcz5hZ3496WJSb3NdFrO4o2
D/dD9WYU1HINVvxT4vk0V6MpZq3jUxsOL9REr+HWIGMpH0C0d0sjXzoQkwuciFKP
H7YRKlyXaljZkPV+HJsLvY3ayWbuaJSfGSAgJWnLY43+keeyB76dr3LIal1CKTQ1
8zs/2d4JLhhySwc6cLY6PqkzpaXlHVoraGAJBhaK7N7fLeZdRIwcEeRCcjckN+ik
NRIRPHB+9q43do/6p1dvL+Eexb8pnTi4/o05eTcDYVPcUN6yF6HWBTNCRyQAZ5zp
QbBD/cMsop75TbNgFxLHg0IC9zWI8wIDAQABo0EwPzAMBgNVHRMBAf8EAjAAMA4G
A1UdDwEB/wQEAwIHgDAfBgNVHSMEGDAWgBTYmh+n1yMhIm6gXfhe70OcgK6SvTAN
BgkqhkiG9w0BAQsFAAOCAQEAUvNgOFk+7UhqjSY/hfodRemCecx1R9IAiH3ONq9R
gr2W2p2wk48AzuUMi8NcyUm6C4TQWNiMeJBvHR0IRaIawS5CBwQxAdB/grVkXhe4
f71+qUiUQl1ZIyCubjo5elXz+T1WfSthVZdzDHVpsPtiaQEuisbcKXU4dhbWGq7O
p7n6JcKOgnMj09SgVyLaOHgB3I8P4uQDNgluy5bN+940euHny0+OCEYHSzey7Cfw
1AJnswM07TEWmy9I7XlSLlfcTqL/AF0qv+M1DR5Venb9vhlGtqJMSv7xW80/zDVg
6gba/+goXsnJhi8jlyuZ+l2npsetk2tllyvomzeMJ3mg/g==
-----END CERTIFICATE-----
""".trimIndent(),
        "legacy-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDEzCCAfugAwIBAgICA+owDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAwwWTGVn
YWN5IFJvb3QgV2l0aG91dCBCQzAeFw0yNjEwMzAxMzU4MzhaFw0zNjEwMjcxMzU4
MzhaMBYxFDASBgNVBAMMC0xlZ2FjeSBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAtI/EfmWZSlJtxLuDiyidJtyjipO3pCMpEJXHkb0eLDVUkuAS
ysyqbKwntbWxo6DWdwrDA5/0lB3uCYdx2x/MlLeLpEcKTw7ivrSn38ejRrUXqJ68
4xfC+04LQ/Ai/byrIQOfhwThUnp2j1mqdGZCDyD9uYGQhh6b8N6DiQPkzhz5WWl7
z6lU+Y/2buFouDttCfwIMA1g8y1TNO/ebn06aYveXmzfI6gVaLQUE4DHTUajDegC
2HB1ibTUZRyOBZ753AJH7dTlhKVwSK1Y6+qrcIbP+RhcGAMT4uDCpOiOJp8Q3Sdx
UFlBCvAB/8hoz9imB1BV7SgBD2F8/CXmEZh19QIDAQABo2AwXjAMBgNVHRMBAf8E
AjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU1sA/86Y7ZwnuF4pEKxLXXov7
fDgwHwYDVR0jBBgwFoAUZbOcgbFcNfmk575JMCFnB52KRD8wDQYJKoZIhvcNAQEL
BQADggEBAG45HE7IoTvZiqurPJ/z2KXLIGcQatTeLoiUZJgHlqeMyQgg2qvMwk99
ehuJ17Ce8UlnFxYd5PbEVPp5PTeND+53ecDsGQELk/Nc2dMZKjXfCc669d6tDPrp
fdpsdY/RKZbDPl4twtnVjWA8wCk703R+2e+CcIpTKa59p3jXS7gKLJJU2f36gpNd
EwFHGrg/OqJxAk519trNMMChGISpVdzXC1UON16rkrbIxFEJrIb9SUFIwtYAxV7Y
MHbEkrbMMENN3qDLnW3P3HL7aZP5rSgIyc0X/dtaWOUYoiGRiO4JJ3aLsAplIhzM
BSTPjNHkw8kTR8HV0xsBR5Ywfv0ImAI=
-----END CERTIFICATE-----
""".trimIndent(),
        "policy-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDJzCCAg+gAwIBAgICA+swDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQUEtJ
WCBSZXZpZXcgUm9vdDAeFw0yNjEwMzAxMzU4MzhaFw0zNjEwMjcxMzU4MzhaMBYx
FDASBgNVBAMMC1BvbGljeSBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEAutZsUf2yLOejevIcBdliozQISwhys8hxH8IH/QZgqWHrVVUTb7mFhn9e
msZ8kfnkv5mWOQszV79oMF9wkPXi0L1G2UqlU7VBoG3U6cvx0OvD1px52pPL1fS/
0TEz2rIi3KiWQkjlNTFoW+RZW2aLs8sf45HY3txwd7tarOL26KFmxTxI7AWQIt6N
zcbzwLEha9bCanNasWpl/N0CK53vnPddEYtKVJtZAI6FUlehU54SO/SObjkhWMHM
U9AgBN1BwL7JKFwKndrYIVCDGfSDZSPoD9fHcuIFs43gaDWyiplqpFxcPOwYiQ0z
Cgezley/NXcFeqhIQ983crwLWFj2qQIDAQABo3oweDAMBgNVHRMBAf8EAjAAMA4G
A1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUsF4MvrZJzmZ46mVDfQA46dIZQJQwHwYD
VR0jBBgwFoAU2Jofp9cjISJuoF34Xu9DnICukr0wGAYDVR0gBBEwDzAFBgMqAwQw
BgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAASTY8RDbyJQDV+L2vprhLN8vkef0
ERQJ/DaAWfPOOFCW0P8iYPG2CAi+zNEBmX2pVDB0jDKRODRDCkDL2oEQ5Gs5H+RM
ZdpDUwZp7/eZ3B+louixrbAVSIftDXPwHCmB2dPosVdiZ5bJddvOw6D/acl2dZdA
o7AayINSFW5Ibll5C9TfL8V2UCMlfssq/sP0L4MfHZVMOb7U/kg1/zTIN1MZnTPA
fRaNkI6vC2rrxqVhL0KmSlFuVRp7DnBLqgQnCDPQ/YubIPgv/EuNy9U9evzf1X7/
MJmj0b3p/R9o1PvyPfeJBl1dNBR68LI7QMmSYe8J/d4z0o1GQZk21AHIaA==
-----END CERTIFICATE-----
""".trimIndent(),
        "ku-root" to """
-----BEGIN CERTIFICATE-----
MIIDODCCAiCgAwIBAgIUKwcwOV8+Igl+SNEoXJ+L/dZWzDQwDQYJKoZIhvcNAQEL
BQAwIjEgMB4GA1UEAwwXS1UtT3B0aW9uYWwgUmV2aWV3IFJvb3QwHhcNMjYxMTAy
MTM1MzM4WhcNMzYxMDMwMTM1MzM4WjAiMSAwHgYDVQQDDBdLVS1PcHRpb25hbCBS
ZXZpZXcgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANPxtPb8
HcpdgYWxaIUjtDX3VONaJV+R3+FayomzST9jgYpa38Pdl/oO1j12uzjpkkiVC4MM
DZky2BURjn6d39ncKHD3ga+PrMmHau+2jGakORvRP1U9/Kw6mMNOZx3wX1DiBnNh
QEzjwtLOCF33zDgyOG1raOqptbu7uAp3b4Bs2WDy2LJSjw0EixewWcCLPBp6HsYC
c+usUujt9KBCueTwlp/ODU6z5gZEnYEEqyZaGG2k1azfdHiJ6SPdhTKXac/LAVzu
s4b2KRAz+XvY0YYMtNhJdbbcthrzPhsFys8xXtS24YwjixXKK3qUaahth5ihC+b0
Z2mb5pBje0gQDu0CAwEAAaNmMGQwHwYDVR0jBBgwFoAUbNEiOm2+YUTp9eTanEHq
l3Ay6ywwEgYDVR0TAQH/BAgwBgEB/wIBAzAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0O
BBYEFGzRIjptvmFE6fXk2pxB6pdwMussMA0GCSqGSIb3DQEBCwUAA4IBAQAOSNAw
+S4E6qjHiUQZgRz2uFump7v+cNeKS+EDgyuVJ8IuDfkCifPd8F3b4Rcu5ofsIyIl
1zwMDbZxxy1+lniVv2Bly0PuDGSkyka5eBFHA/EXFZKdsqpHWUUHADvXNrS6Q+Uf
AhxIv5lSDxx/HFs3Lm7/G03lL6bFet04jgxMyc5rws1tXBnCIkr+p9tK97a379Lp
Iwd3FfTzKfBKXM4sWIF/FNVsa9zjItaPn+agwRBNUPPLS/bZy8Z6jEbFKC0sPPsr
HFuWOOdDUj5JpiuhZ8J32zaef6zp6Xx4PL/xVY6Q1SOmQ3rniPPh8I7uTT0SxmUM
gNxV5Jdf7TQRTdTf
-----END CERTIFICATE-----
""".trimIndent(),
        "ku-absent-ca" to """
-----BEGIN CERTIFICATE-----
MIIDDDCCAfSgAwIBAgICJyUwDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAwwXS1Ut
T3B0aW9uYWwgUmV2aWV3IFJvb3QwHhcNMjYxMTAyMTM1MzM4WhcNMzYxMDMwMTM1
MzM4WjAYMRYwFAYDVQQDDA1DQSB3aXRob3V0IEtVMIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEAvOwEVoKkqwuP4UmssEX2UpwtM1/XIl9MVLD246/e92sr
6NeBCsRQHt3VsHF4i0q/1Vy7c+LkxHjqIUfO6eMup2HPWcT0oi2KwvrRpeYrQk7r
RI69F4gskIH4222Hw9RK6RJt+aFa2zv9vVhkGoF0V49xXqJGNs85a0yVvZEuIKHB
4goLCW/hIalD3SyFDXJQQIYkbA1hDr/KnHTCfqCQADeEnGuCYDjsS85FH1CakqoZ
OWuE0ocJgHKdblxoYR8lkzk23IiYKSB/UdhEabzcN/T36DzMPyHejoqXOmhI94be
iweFcre28sHuIPr8N9xlflJLyRg3eOePvCUem561MwIDAQABo1YwVDASBgNVHRMB
Af8ECDAGAQH/AgEAMB0GA1UdDgQWBBQDc977Ohs7oZIHvA147ZVodH0NvDAfBgNV
HSMEGDAWgBRs0SI6bb5hROn15NqcQeqXcDLrLDANBgkqhkiG9w0BAQsFAAOCAQEA
UJ1UsWYAeeAmZM7Ecj5z6bas2bMK7ED3UtMZ3P9LoUrpM0sQa33xXEuB9Joq6xMg
ebkjWixwqnaCAYrvL13l3bzSWkXFlOwaECh2UTQA65txfuAMYJZggY1xyfYuU7II
Ac+K8qTqvG6y4R2Hltku9+1iSGrWaRU6ouo31+6vsUIVpryPouBRXxJsl6jEEhCO
/9vwYw4IKP3SBK8hMPW15Rhb6Ztn09hIbSJsf7vKlniW5y+9AYJ6MKE4/OzTJAsw
fVi3eKVkIeasVzwNuu0AFO0bWW8BHfZhLJrALWHyOfFytVq97XtZ/86nSAvnFoDO
Fa4se8lgEDC+oDmaC/3bRQ==
-----END CERTIFICATE-----
""".trimIndent(),
        "ku-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgICJyYwDQYJKoZIhvcNAQELBQAwGDEWMBQGA1UEAwwNQ0Eg
d2l0aG91dCBLVTAeFw0yNjExMDIxMzUzMzhaFw0zNjEwMzAxMzUzMzhaMBsxGTAX
BgNVBAMMEEtVIG9wdGlvbmFsIGxlYWYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDvihCq3+bG2M7JckesWzWWcEDs+7xWZRj1ihJr+2Kb9hwdpLII0rs0
6u9m/EsbxixrmwR1BFxYaSIUVsK98AzMzIhkEyCinqOCI8iymXyWPvbKLQMkWZl7
+/cLCFgvr2jWzs3EATGMOYbrq6H5lrwet/xcYmyCjCPdnikZZaBq3ofyVfifKHeC
4DEBD2tPjMir4/DRdVJlwe9I7iki/9mzJ7mBjniIYQE1XfM4lWxLj5JPdg1Mz39x
wtfY1m28bout3eOrJzsYK5qnmFmTxUrFC0daLpaSFwRzeR/5oUoUk051KxDXxrQu
XXy2rK5VLo7cn4UfBDxUQRK87/EQe8v7AgMBAAGjYDBeMAwGA1UdEwEB/wQCMAAw
DgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBQHYUrPi3sBCGf8EU2vVtx3Wbo4djAf
BgNVHSMEGDAWgBQDc977Ohs7oZIHvA147ZVodH0NvDANBgkqhkiG9w0BAQsFAAOC
AQEAiyR1I+JH2gUfvcyFVeaLlv3GyQw6RnWjNiYYgpY96RwfBADB7ToauRGu51F8
AXir4aZI7t8rMu1k4Jj9PTcgyS5HylbCS7F4tnPA9jwELBpBAlw74z5saOIPMHz+
Wgfj+H2N/Gyc0xdP8fPQZZ1F/h+JZUdIozk4ztEr0tBt7B8S9dAnX4bfMMDXKi3B
8ahnDMYP5vp7Xk0TT7BSaXrnsjI4r3oGwqwMXP01NhT5jaWfdbwhmzDnlpGbaoEf
BCi2L17GzUhVTAr83pbFQ54yeKmCRH6GNsZclR7cYJCLV/C3olEQAkymlIj+AyfD
esX2nM6gPvhBHqIPo2+zH+tsqA==
-----END CERTIFICATE-----
""".trimIndent(),
        "client-auth-ca" to """
-----BEGIN CERTIFICATE-----
MIIDOTCCAiGgAwIBAgICJycwDQYJKoZIhvcNAQELBQAwIjEgMB4GA1UEAwwXS1Ut
T3B0aW9uYWwgUmV2aWV3IFJvb3QwHhcNMjYxMTAyMTM1MzQ4WhcNMzYxMDMwMTM1
MzQ4WjAdMRswGQYDVQQDDBJDbGllbnRBdXRoLU9ubHkgQ0EwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCy+BwiulOoHV5poj2iMm/3PWkhihJ5vf3zOcyT
81smPMvrD9Sf7+VyNQoc3ZsOc1n6aFaeskW0/pbOPbi8/ITcfWhjKRQBF9NUF/qr
22EkMLqgJFrAOTo2A001kfPiNiG7c9ynf6MmjgJO+zER0hgmT/5wDptHKzan1vrs
P7qiNyIAVX4+BrRcFLTpz7J73Cr0iAh+OcSL+fe6roFTb2PafocQzn6QcjGSAuu5
giYhyIxZli8hk8oTnONJYuKLl1vTLAMdvs5DEB2g7Of1GRQwxxTOkelM48IzocPx
heXahz9lGnNgb/Qhur1c/48/nFl3h1T+hEfk42Ib+fALsoELAgMBAAGjfjB8MBIG
A1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMBYGA1UdJQEB/wQMMAoG
CCsGAQUFBwMCMB0GA1UdDgQWBBR9LrdUd8yD9pu//JXmu5V0G3OtMDAfBgNVHSME
GDAWgBRs0SI6bb5hROn15NqcQeqXcDLrLDANBgkqhkiG9w0BAQsFAAOCAQEApnQO
oSrG8UL9OaNVeisvDWSjcMBK3fV39jHRqNWAWRMota8gD55Xrid5qUuj67ABK6Ci
pucfMvdfyBzpp78/j8o0vS5jy+GqHyQ/9oZEggpc7P22+OCAsfAXII5vf/gX1lTH
rsbXFKML47QxATmVAoSCHtviFlxUw1woKgbALUqUeWdxVm5juBkyG6/0rn2hbqyT
lph2nYP1/qcaJIqGuNbcG7wLraMryPUU4JecYwTYE5PRDPI5qS0EMUsEE39On1sP
MhsxckLcunqP/7nm50tBeVcCLGq6donh49BS5F+e/ziCagHH7l/TP7RROikyBNNS
fEbwN4BDoAoQhwQ4bw==
-----END CERTIFICATE-----
""".trimIndent(),
        "server-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgICJygwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAwwSQ2xp
ZW50QXV0aC1Pbmx5IENBMB4XDTI2MTEwMjEzNTM0OFoXDTM2MTAzMDEzNTM0OFow
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAyKYG/ftxgRUtgFGoO7O7TbutrlbbHur/sVQ9BkZmiSDsjEPd
gyOXmmX26U1MWpL+8qWZDu6VsYATLvTwCM0kpRjROd/vJzKhogrgZxsnMIYUsrzb
qYQjUbBAd1Pflzq3higMj0JR2z2iw+RFPhoCzjfVuBUHXsJZwp3pA1ax9imjeEQ/
AMjMLmDQOOYbVFz6lNprKAxYX3v2tVNR1FVToxSrIFXMUunP5OyTIMVYJjBYRKk/
ClgK9u1HTVP+RTwcIE7NUIA7agWc4Y2mGiFYZFzWUZgJ1f12dgJoBOfrX3S1I6qe
2XK8Buos+N7FtCPxjevAFiu6oL0sugnqSQzihQIDAQABo4GSMIGPMAwGA1UdEwEB
/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1Ud
EQQTMBGCD3d3dy5leGFtcGxlLmNvbTAdBgNVHQ4EFgQUDTR2vT4N8n8kk4kSKw5L
RdFzh/swHwYDVR0jBBgwFoAUfS63VHfMg/abv/yV5ruVdBtzrTAwDQYJKoZIhvcN
AQELBQADggEBAH2D5SYQnFiQvLshXo0XwZXZiT1+CIrBqSyVvt8wq2TQADeQJxzl
6Ysnnuh9jFWfprWaDqISy9qIVDlIq7/VO8wTatwqSqZGzebpSsWEcBSrojKF/pB4
IZqyc+YHSmc7zfScLZdk0i0MgY6KxALH/w9bZS9mb1Mn8sdPyT08KpsbRnZeVsTL
eyhVWQiXsFkrIdAheWBPHLZsmkSN/FxDImCrxSqG9xWgKXfUTULcpYAFkTU8UZ6Z
x2mRiZspA5LC1GWJ7YRGBpqPiK44XrCmHz7y0WOacvPSgnHwI45TX8eGC3jSUhlU
ccltCBQyP7NTnVAr/371dTjyzGOs+XONaa8=
-----END CERTIFICATE-----
""".trimIndent(),
        "cn-intermediate" to """
-----BEGIN CERTIFICATE-----
MIIDOzCCAiOgAwIBAgICA+wwDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQUEtJ
WCBSZXZpZXcgUm9vdDAeFw0yNjEwMzAxMzU4MzhaFw0zNjEwMjcxMzU4MzhaMB0x
GzAZBgNVBAMMEkNBIGZvciBleGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJ06yUgL4vIMeeQ1hrU7VoOowy+sb1hQNmReRoafz7T8Itta
Nt3rj6O3JQPPlI0+6n87HPz86VMmUX972KPbhumQlMWDZiGSm6K9PrZr6HIqe+Nt
1xLjcdvpC/hhM4JrfPppAlO/RZi6a9qirH7sn/1F7JOKL3vHQuU069Q0L6XKX99f
DGrFXBFlN8jHFiMvmzUU/DT1OlJVzYZy5og479wf9ohqkGpUY+egUaO2rdHZyC47
j5tOeUBapJrK/y7EjHO11OkHsIpP2RH7L6SiqZT4uz/GesW7RDYEfuf+C/yBBTt6
5C4H1NlcpkxbB4cVJrtsYD3DVBWb+/CR1til4Z8CAwEAAaOBhjCBgzASBgNVHRMB
Af8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUtHpaXjfMNQPP
GlfKWopcP/wU1KkwHwYDVR0jBBgwFoAU2Jofp9cjISJuoF34Xu9DnICukr0wHQYD
VR0eAQH/BBMwEaAPMA2CC2V4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQB5
uPPTo00vBeJ9a56oiRh/6m4sMIMjAJUK6XGa6llj1uiWgLrW8UAXpI89pYO5NNOq
9At/nsvuHXVpG/rFoJCvJL4bMl54GWfgIn5PpH1eQl/Oo3RPul4VSaZGcuy/NJaR
77x3CTilihuOmLFtkjYs5OTlkUcR29uVcpHks/h8xreAH/Xd0xcE8PW3oo1q24t5
wr7bJQ9p5UXflVfoCPptprZqr7xffRfeKtjpY9ZzCywPccaXF/+ZmOUbNKhcHC4+
0LUP1q22S5nvGFAICromWtAJW4cnANeFp5ajqfZ5UDoev3LZzb+yWqFEXy5tqpY6
UaJg3cg4iOdiUhsj4Z7m
-----END CERTIFICATE-----
""".trimIndent(),
        "cn-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgICA+0wDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAwwSQ0Eg
Zm9yIGV4YW1wbGUuY29tMB4XDTI2MTAzMDEzNTgzOFoXDTM2MTAyNzEzNTgzOFow
EDEOMAwGA1UEAwwFQWxpY2UwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
AQCSh31Rua+h9DgxLidX5EyXTydQtTOhg+X6GxX6+L8p9CFQCmRR0K6msImkg1sq
UjVqtc+Dq685KujSn9TYFduoMiYMQjPJLjdnV1VcFBFA2dZSa/svKQTYHoj2FrWa
JTNog/pFDR17hUEYvvtiJCjXAgdfDvUtRjIlqoElu1LTMpMI7/YEMz2uplBZKVI/
TNh7vUm2U8QmjadXKoPv+OrVqKTeo1VhNF9BKUgGGSd0QMDpKM2iZJMwxF/YGLiP
mbJtXSUb6y+MAqVMI6JMGxlFTjRbEUkRCyEz6G7AwNs/0uJyouTvYN4kHv14DXYl
q/Vm2pH/k+AJ2s6c2BjZWNnZAgMBAAGjYDBeMAwGA1UdEwEB/wQCMAAwDgYDVR0P
AQH/BAQDAgeAMB0GA1UdDgQWBBTTBNQMn9e8CrBTrivF3mwVUB3n0jAfBgNVHSME
GDAWgBS0elpeN8w1A88aV8pailw//BTUqTANBgkqhkiG9w0BAQsFAAOCAQEAdKTT
RZ6YyeGtQwQ6+m5NfMkI+kJH+NuEMLT1w6okBoU3+wFuzqtIUyb6i0XXC0xkELJb
9561JRZg4b0Qxwm0XmbO0TEzlnYe5Qn95PPhBAYw8lmjp8n0Q/aN7gID8IfwKfN6
t9+pdPIVSBm0Izs5KyIxdXxLPRdUtiDMJmmvq+EQEgdLFc/cuUCy/ZxAUV8beLJz
VuWVF8N9wSndq+7tnZSeOeoNZxACl1hs2dyGtpRLDiOj1I0I/IStQkHR5Ou7xrxF
2vs82l4fs3h+IC3rOC5k7tN29GeKFIj7ixyYBLNbTZUkOEsXBG1JhIN6WvwqTxDD
D3zvu/y9wxt1F22kuA==
-----END CERTIFICATE-----
""".trimIndent(),
        "narrowed-intermediate" to """
-----BEGIN CERTIFICATE-----
MIIDRzCCAi+gAwIBAgICA+4wDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYQ29u
c3RyYWluZWQgVHJ1c3QgQW5jaG9yMB4XDTI2MTAzMDEzNTgzOFoXDTM2MTAyNzEz
NTgzOFowHTEbMBkGA1UEAwwSY2Euc3ViLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlI3GO2NJo/hoGPLKptbykPBzUqibMVqCHu9T
776Ud5z1DLFAq/jkirvnCut+JmFJTVUgX8Ood6QcZlmcEdHLBktktufCwJhTK++9
jG6EbOdxs4Z1if085swQZs4kcMFceTROeQrQI6StaEQo6Q34JhkU7DoYZU7mdfbp
47m6dY0zXLXQFlgVO54fgdAFrZ6ysejWW5OAAvh7r1QBDFmsnQXy+PnkPYk4LNel
L5jLOMUpS05swV5Sm2reQTqgJ8+b0X4hRgXsH8FSp9ROv95cCxP01r3raDrqmTrl
eO+CBX8IkGyEOeGIkSYp78aAUQiBGlF4/3j8CwXdNlbCAhZbmQIDAQABo4GKMIGH
MBIGA1UdEwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTO
2f16YBNfuvfgFDo5EefwvZ/nizAfBgNVHSMEGDAWgBRIjtBpmTz08gCyL7oqC1RG
DbwfzjAhBgNVHR4BAf8EFzAVoBMwEYIPc3ViLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBCwUAA4IBAQBsCuptLf/x5kwmXNeuelgEhoPnV/Mff+GZAncJ3VjQmVkQovp9
xJHXaIelkOnuzo2OzgNG2QWLcPXRLusmdfXHJ+LDkwFdcjwcy3FDRUDGs3pIW39B
CJeBToTCEm7i1T4n2JLrLliRrmw6Ds16Za8YGGZkYaWAlophc6YNZZjKuQ2/cgP1
J7Lp6y2fayAWybAUIo7Dxo506I6zij0nrv9+n72hAH6UwEACRZrv2WMZ+hwrZUdP
jOc5Jr3Xq8X4E0Gg+hwI3VD5d8U8c+uut1ICq058CbF8TcgSuDyLHhAyQqDStrEq
//vBot5vJoAYfFgtWyDqjPwPeHJstK98cZCY
-----END CERTIFICATE-----
""".trimIndent(),
        "first-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDMzCCAhugAwIBAgICA+8wDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAwwSY2Eu
c3ViLmV4YW1wbGUuY29tMB4XDTI2MTAzMDEzNTgzOFoXDTM2MTAyNzEzNTgzOFow
HDEaMBgGA1UEAwwRYS5zdWIuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUA
A4IBDwAwggEKAoIBAQC/GYiHgstQFwQPqpGZJE46UPoZ7McCu1rvlxUe+SZAAcpo
8qRnZzu+wCswDLHxIpSzfj9IeL3ERd/yWcFX7Qlfz28maHyOlenpZAW28LK6Gh8t
1MlMbFM8dU1DbmXkprqdO5fGRkPQrAcEK2q1pq65X9IFY+lsYgj8SMfxlsAbmWOY
sI4II9v3v9CZr8cJQPu2MqWhLGO53aCnUAM4Q3Bw3FvyON+d57bHS1swsc/LUDFX
599GLIR3JOa7rnDPLiopCfMRCu0SZHHmx3ZGfvH+e6+HLC5S1qbZ0QpUiRRw9F2T
FtqtCbwPBlqiau+aJyPiKn6uBQe4fFKFTrMIdfuLAgMBAAGjfjB8MAwGA1UdEwEB
/wQCMAAwDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBRpBXCLjK+SrIy4mGgWtcx1
2MLkeTAfBgNVHSMEGDAWgBTO2f16YBNfuvfgFDo5EefwvZ/nizAcBgNVHREEFTAT
ghFhLnN1Yi5leGFtcGxlLmNvbTANBgkqhkiG9w0BAQsFAAOCAQEAfMjaO+EMnAwO
PwJ0Gtdo2BJjv6La7hUY765wfN4KqJnoVf1py7mrGBvuNFzLqvZP4qI0N/VC/fLh
pIHxnhtHPM5U4KfZxY9Id6RQcTl/BQFkN3O7E9QKKl8w0zVV4XEa7EOkjYxW7g6u
UiaMK27z1E3MyBLXMYor77kSIaHC0HvED7MtlSDPFzlTzTtuvZ+JbjiLXZto79l3
hOeBZF4PqtuvRgjUWrOavcJqhvUoEdqkj5iS58L+MVhWn2QcBfya+lI8u5p6SLrK
FlEIxd/Yo//SFAaZz5ivZo6sEFVYcizO6GLfclX339P6BVCVxEFHXA7L4ao7YLYs
2elfoaIWIQ==
-----END CERTIFICATE-----
""".trimIndent(),
        "plain-intermediate" to """
-----BEGIN CERTIFICATE-----
MIIDIjCCAgqgAwIBAgICA/AwDQYJKoZIhvcNAQELBQAwIzEhMB8GA1UEAwwYQ29u
c3RyYWluZWQgVHJ1c3QgQW5jaG9yMB4XDTI2MTAzMDEzNTgzOVoXDTM2MTAyNzEz
NTgzOVowHTEbMBkGA1UEAwwSY2Euc3ViLmV4YW1wbGUuY29tMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwYfJC+Zm1sNcGm3oiniE/WMOkls7D7awaOcq
9mMepckpy6IH0AUwRbgtRjb/1sShtxILxDJlhB7TcNCIyioBb+7EibTlFxp0dFjY
ga40n/1NfQ/LF0c82TYYn3q+I4YFcu7fOjdlfu/roFpyEk8UYHaMVZ1RFhy/UTyx
2VMItHcvH/EJMIPXU5x6Ranv6UYxVPgsziwH5hwC01TJKd9Md9YDCfhWaXtAp32g
lkB/rSOqQBrTgSRJD3P5sbOr2HfKrhzZrTjh7CKcqmPUvrLlYmGQB0S7G02EKuHm
dS4JdUcj+tQxbas+a2/oX1LMOpubIPv6gz3i9Uhoy1j1G2fJswIDAQABo2YwZDAS
BgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUYcx9
dZp3ZcVVTrkxyI2FHNU7z1UwHwYDVR0jBBgwFoAUSI7QaZk89PIAsi+6KgtURg28
H84wDQYJKoZIhvcNAQELBQADggEBAHY3Xl72VZ+YE27Pf4LwTm2MC4Gc7i8pzk9j
MrPlRi+VebHRmTDdT71vqa3lWIoTnn7SocPNsxDPEs+smixEAY096vYgX3IrMv58
Ik/1Bf7YSpAv82V7YuDofKN7DMjDEOEveAY7BhaErgOZPfi/x2enGr+ztrcdUx5i
GBmVhSDXhXXEdHbBZ+e9JW7IXFRxRMx8RYAWk9XZiL9tDIcuvPitgsPcYglCfP1O
LOXXq2RV57K5/GYha2vBLbuXn326oE2LwHGc8V3mDYkQtSvTeRsuDubSHZ+3E3+v
SDgK9AuipVym1898T2ecEu8J6qapDg/4qIKSCkTcbE3Ou4ofYe4=
-----END CERTIFICATE-----
""".trimIndent(),
        "second-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDLzCCAhegAwIBAgICA/EwDQYJKoZIhvcNAQELBQAwHTEbMBkGA1UEAwwSY2Eu
c3ViLmV4YW1wbGUuY29tMB4XDTI2MTAzMDEzNTgzOVoXDTM2MTAyNzEzNTgzOVow
GjEYMBYGA1UEAwwPd3d3LmV4YW1wbGUuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAiJSOk8oYeW+aEtC8meY58JmR8pmiswXgb3npRNgm2iEz39Fo
VHr+OxbkyqAOyD1SG/b0VEZtEuO62EJ726hfrVxm0uIeDLXl4WzPU9EGWVeic6bh
JgxuSxT6bHAW1qldmtbbL8jz8Jps0mWoAIpJ11ccTSJIBr2asfr7GSjy9bnkOGUB
8RISyXlkOz7Lyltjf3xJWi2kEU6CQVIuQiJPDllN9Ur7TE08cPzAGO5BcRu1Dtfd
DKrlDel3eM/+Soxw+6hAXsPc0Baeu+6c4CFrC6DVwUHKZzquTgV7DTX1L3RQ0tyw
OILdSU9xEG8II585Rjoj09opO59e8EW+hxBdsQIDAQABo3wwejAMBgNVHRMBAf8E
AjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUj5Kr6OVFThbUfpf/arQitTzW
37owHwYDVR0jBBgwFoAUYcx9dZp3ZcVVTrkxyI2FHNU7z1UwGgYDVR0RBBMwEYIP
d3d3LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAOVbQL9zV391JshPwC
ykCMZMnIZwUoO48X1RYaof3diD9JPR/SVh57ifZ94Eu8qzgR7UYvlf4D8rax7OI5
5NcLrOuFQ9Cml79+IxqFYemc2GbDCq2LC/ILV4vS6KrNTCWPqoPrwTGRG/rYhy6B
zXqJhiPYMDxq49L/plKPC63E6jzP34xFHsTurTo5iU67wJS/sB9m72Sa0i9HbboG
V6V4SA8s4CEjrv8yV2HU+n8PLquqk4b7g8v3IhRLcv3djWQx58LQLqo6Vw5t4eDc
GwqTRuFZyX59dbXeG1ReeM4lTCZYs+8+7qI48SuNf3K9yFXsPExDadXJvoWEWv9P
yr7o
-----END CERTIFICATE-----
""".trimIndent()
    )
    fun pem(name: String): String = requireNotNull(pems[name]) { "Unknown fixture: $name" }
}
