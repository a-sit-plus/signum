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

    suspend fun expectValid(root: String, vararg pathFromLeaf: String, policies: Set<ObjectIdentifier> = emptySet()) {
        val trustStore = setOf(TrustAnchor.Certificate(certificate(root)))
        val result = pathFromLeaf.map(::certificate).buildPathAndValidate(
            CertificateValidationContext(
                date = validationDate,
                trustAnchors = trustStore,
                explicitPolicyRequired = policies.isNotEmpty(),
                initialPolicies = policies,
            )
        )
        result.shouldBeInstanceOf<CertificateValidationResult.Success>()
    }

    "valid end-entity certificate may omit SKI" {
        expectValid("root", "no-ski")
    }

    "a legacy trust anchor need not contain basicConstraints" {
        expectValid("legacy-root", "legacy-leaf")
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
            .buildPathAndValidate()
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
