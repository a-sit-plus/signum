package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.SignumPkix
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlin.time.Instant

/**
 * Devil's-advocate regression tests for RFC 5280 path validation.
 * Each test pins a specific clause of RFC 5280 that a naive implementation tends to get wrong.
 */
@OptIn(ExperimentalPkiApi::class)
val PkixAdversarialTest by matrixSuite {
    SignumPkix.install()

    val validationDate = Instant.parse("2027-01-01T00:00:00Z")
    fun certificate(name: String): Certificate = Certificate.decodeFromPem(PkixAdversarialFixtures.pem(name))

    suspend fun expectValid(root: String, vararg pathFromLeaf: String) {
        val trustStore = setOf(TrustAnchor.Certificate(certificate(root)))
        val result = pathFromLeaf.map(::certificate).buildPathAndValidate(
            CertificateValidationContext(
                date = validationDate,
                trustAnchors = trustStore,
            )
        )
        result.shouldBeInstanceOf<CertificateValidationResult.Success>()
    }

    "RFC 5280 6.1.4(l): leaf SANs must stay inside EVERY permitted subtree (intersection, not union)" {
        expectValid("mg1", "mg-leaf", "mg-mid")
    }

    "RFC 5280 4.2.1.10: DNS name constraint must not sanction a bare hostname suffix match" {
        expectValid("nc-ca", "nc-leaf")
    }

    "RFC 5280 4.2.1.3: empty subject requires critical SAN" {
        expectValid("es2-root", "es2-leaf")
    }

    "RFC 5280 4.2.1.2/4.1.2.2: empty subject with non-critical SAN must fail" {
        val trustStore = setOf(TrustAnchor.Certificate(certificate("es2-root")))
        val result = listOf(certificate("es3-leaf")).buildPathAndValidate(
            CertificateValidationContext(date = validationDate, trustAnchors = trustStore)
        )
        result.shouldBeInstanceOf<CertificateValidationResult.Failure>()
        result.validatorFailures.firstOrNull { it.validator is CertificateValidator } shouldNotBe null
    }

    "RFC 5280 4.1.2.2: zero serial number must fail" {
        expectSerialFailure("z-leaf", "Serial number must not be zero")
    }

    "RFC 5280 4.1.2.2: negative serial number must fail" {
        expectSerialFailure("n-leaf", "Serial number must be positive")
    }

    "RFC 5280 4.1.2.2: serial number exceeding 20 octets must fail" {
        expectSerialFailure("m-leaf", "Serial number too long")
    }

}

@OptIn(ExperimentalPkiApi::class)
private suspend fun expectSerialFailure(name: String, messagePart: String) {
    val trustStore = setOf(TrustAnchor.Certificate(PkixAdversarialFixtures.cached("es-root")))
    val result = listOf(PkixAdversarialFixtures.cached(name)).buildPathAndValidate(
        CertificateValidationContext(date = Instant.parse("2027-01-01T00:00:00Z"), trustAnchors = trustStore)
    )
    result.shouldBeInstanceOf<CertificateValidationResult.Failure>()
    result.validatorFailures.firstOrNull { it.validator is CertValidityValidator } shouldNotBe null
    result.validatorFailures.map { it.errorMessage }.joinToString() shouldContain messagePart
}

/** Embedded PEM fixtures, mirroring [PkixDerFixtures] so the suite stays commonTest-friendly. */
private object PkixAdversarialFixtures {
    private val pems = mapOf(
"es-root" to """
-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIUHAPb3D5mO95Lo2Z+wwdO5YWFVfMwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHRVMgUm9vdDAeFw0yNjEwMzExNjE4MjZaFw0zNjEwMjgx
NjE4MjZaMBIxEDAOBgNVBAMMB0VTIFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQCr8KN+tIVIVdR+xy7Znr4O0IFv13h0HeBs1dILBpwAbZGTZE49
caUZTl9f2pZD1fViRao/AT5eFjm+qgoZ6fwSUzFLfELNEI7XWvvQEUiQ+gNN5zkr
JPn4woLHeqY5g8yIfdgV3Jnb2jkzRXswGcx7XoPV17AXBfapY/2VKLkApParnZLW
84rYtr+UvD21HoWsNUIkNtEJZA4F6PC9j3hq+hN7MTQln58CHBX9APVYJZrETnM4
pkTlzX3H2YqvOLUbxSSP9cMp2/5wiea73LPg3/zKLgvdhsffcf3dSYOCxXBm/2K/
klUiAJRqiNF6e4iMb2ruEL+H1FXAhT7Y7Cb/AgMBAAGjQjBAMB0GA1UdDgQWBBSn
kdQcm5ZSQVd8+8pY3ti8JqaoDDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDANBgkqhkiG9w0BAQsFAAOCAQEAB5UDH5LQ+htCpUI52aUgafuheTsmkBKe
Q8OgG5rs9mdM0tYGTzBdZPY89xx3D9QSC2pF5QyCv6KOqvDphdNea/ZS8hCitljh
vfvAF6zZoxu/6d4Za+leAH0cLb0ysVmrtJRgWORYhR4BHGxNmLxVnwGvAWLYrGng
9lfyqW1JHuPlK+7IlKDvkvu4JizPkfYh2E2RgMtMAWSNmcQWY3h44mGBeJv8CRUA
C76UobBwZlt98ECoAS7D6U0wNrLMyHqRNV4VWhDsK8H27Qt/6Ct7K0c5DSNRE69Z
ZotFqMEKO/SYszC2z0jo6FdoOCI17FZmalJDwaY6dwaVfdELULtiFA==
-----END CERTIFICATE-----
""",
"es2-root" to """
-----BEGIN CERTIFICATE-----
MIIC9jCCAd6gAwIBAgIUCyPNoCvywgHFt5fccjj2LXrmAsAwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIRVMyIFJvb3QwHhcNMjYxMDMxMTYxOTU3WhcNMzYxMDI4
MTYxOTU3WjATMREwDwYDVQQDDAhFUzIgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJj0lvepxJ8IWiR8GCQnWwuIeRvG5uOTb9KrjGJiP50AOGD0
RGdv1s24mKdTbKT8BkIrYp4S3kJVafo7RNDbwwSXoE5w81x6HHtjbziGsXMTkCQq
RMS0Cy4a73b4MhCEmj3Ed8U1b8flDAlE5Zs/Lpd6VLoyP8PUC302KZ7D9QaExpBR
enxqABuWDehJfdvjvuDslR+k4tJtkSjclZxGPQ5QzmtKl4JZDTLSQi1OB+AjcFlE
nc6e5Wu6uHCcQnMF149XvC/K6UNsOTQGFhXAuyr1ULwJ7s01NddKbRhsSr1FhdZg
ESTbUFAj7lhnmqH/Yad4IXjt27RBcfupmDDQ3FcCAwEAAaNCMEAwHQYDVR0OBBYE
FMUqYjvUo7u8xAB1Zvxs/K76Hy80MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQBRzJJ78H/4okomLidhWusLYyjU5odH
19dFm4R3Z3YRCq/xKOd/X9yUKDqAVqJvu+tOzkHD3stDXoAdDZxYmBn7yqjTPWH2
kBlT8c06iztlBXBKIFF81A1upMcqlsP4tr2ISnaY2XvkctzEGdBuhoOvxRORtDns
E4jAjGMpdARJaklV9gpe5U7fxqWp9/Dtx069MzWKzo7ML150j1GO6TN5gN3A8yET
wOBcoXdAVTFpd3apN7AxrLykhjuBLI5A9cCc9zkLQLDjVAsFL/ED+xSI7Zx0YU4S
HuOQQOXL5vmuf/0XW/UDaT+kMgomjMobqkTFLkWKCMVP5tZWzYNUxHDC
-----END CERTIFICATE-----
""",
"es2-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDCzCCAfOgAwIBAgIUcgNRGpp9bwJnO5KnvK9Xv93FiO8wDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIRVMyIFJvb3QwHhcNMjYxMDMxMTYxOTU3WhcNMjcxMDMx
MTYxOTU3WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6KpjELKb
+5QzTmyz6gWveTVkUr4vlbV9OwMcUX4O2L7L974y/NL5bUvtXzP21/TQUEKdf5On
GVPcHWvJjCR6kEo7kSAfl4LpRUctEYOzLVupwwsv04yMBX5/PkhvPzsN75xla8hT
oLAaGOPAyD75vFfOTJ/0URjp9VvAK9wwiRvzttmBPigNj876sRkjMGEvQcVga6dO
U0dul6i38Pnd2SB3yqYW1lQubQKnTGUtnRkfLs6o5Y59+0vV5YEWSUJTNjwz7/wW
Ky7mJugsa+rU6pfhMPpsHQY3heW9ldceps9z3ID5m+U0ma0wRK1k5YMBNWDw39nw
JWtBTvsRSCFxYwIDAQABo2owaDAZBgNVHREBAf8EDzANggtlczIuZXhhbXBsZTAL
BgNVHQ8EBAMCB4AwHQYDVR0OBBYEFPxVJo5qJrnFxR+v90zCWiXAIDB0MB8GA1Ud
IwQYMBaAFMUqYjvUo7u8xAB1Zvxs/K76Hy80MA0GCSqGSIb3DQEBCwUAA4IBAQAj
bDoBQeM6GOX1DHt/78UV2NkSXL1D07NcqvHefmvESdCKSCPJv3t6oIn9qaZ4aqt3
fPmPvWT6A2NW5QO+iMt8/UizsHQWJwByqTosRGcVh4xgUC9YOhFwFN1lylV/3OCt
jwR2vtWhwlEwGd5V8M/8EZs6O0DQlrAp5ZvuvyO8ThBbHovp8N7IV1WGlPeiN6vu
hDZQrBeNvcZDkw1zMg9xIpN3/IKrXtUC10lkT1Th+gy+G6/ilCt7bdpq/QdYCOnL
bLmYVhSCbRo9iQoLJ9f7KGR1LfHukV/zrNfyeg0hUJwGdaRRhNj2P6oUIwT3CoZS
xGUYQqUeaXt7VqcWqwFd
-----END CERTIFICATE-----
""",
"es3-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDCDCCAfCgAwIBAgIUcgNRGpp9bwJnO5KnvK9Xv93FiPAwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIRVMyIFJvb3QwHhcNMjYxMDMxMTYxOTU5WhcNMjcxMDMx
MTYxOTU5WjAAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlEOmwX7g
kHMpzhvAgmjeKLrKOi2bC/5VNyDLYWQt797Fkle29gGAugY8od0n6vcSxEOPyEnc
sUW5Z43ea5aEwPqW+ux/5BR9/2/GYxzb1B9bqH6c38j0p0bgqCf/mSQ1rQbdmEDW
Xly3Y3VxJUs9XQH2fNagu2Cz/ycvS6bljjxZhtkw/sBujjCalTAJ2ertlSY0GhrJ
pzyLrGAbzqX5Skhh0I6yCtFci9xrsML8iepxYpWp9h01mO0ihoRpQfX5hz8Q5QDD
BVjX4qaruVAzyPhmvfuu2FzoR1lnWYwaQ4B8rGx0fPEB3N38nXZNkQL83iQlWkEv
gAD0zoE+IWMSvQIDAQABo2cwZTAWBgNVHREEDzANggtlczMuZXhhbXBsZTALBgNV
HQ8EBAMCB4AwHQYDVR0OBBYEFArAboKNZGxAmEg45GMDlpaKQN7OMB8GA1UdIwQY
MBaAFMUqYjvUo7u8xAB1Zvxs/K76Hy80MA0GCSqGSIb3DQEBCwUAA4IBAQAIAZ/G
PK3gF5ht0UUtiKmKnxCw6Xcij98V9wMPxtXTHgnqjHdsHb3X5Q5sGdN5fqojCMDF
iV+LqWBiNC7YDvJN6xBlWDRkQwyBPvEc3K2vERtsCP0qcD0cwiQMOU8vJZPYQd7E
zQUgJTEn0e8e5P5ZgYpG6EFonkC71uHQ0KsvozycyTxFqe6OcToZbVreWv0WEFKS
GGbO27hhS2EhuKdxfWki6jyTKZLvwUfhG6O0xNMbl0/9YqgsV2HDb9RkZ3Yn8Ot8
TzCpDCjx4WdnO923ys7n+bJIrYjUulhtFDtkLRVbIPhhqZWMydNRKfDmvjQe1kAw
W/qdEqlaXdjLBBu9
-----END CERTIFICATE-----
""",
"z-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDGTCCAgGgAwIBAgIBADANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdFUyBS
b290MB4XDTI2MTAzMTE2MjAwMVoXDTI3MTAzMTE2MjAwMVowGzEZMBcGA1UEAwwQ
WmVybyBTZXJpYWwgTGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
ANQ4do6UI47oC7PBxJhq2Ehl32ksflZ/sZ+prROF+5jCaom6i83i0rg5Zmiw2Jcb
5dYEGcaAwjjiGVJxzPcIdnpfYswEr26Q3X+dTLfDt5NTF9sKE3S0BtWEaRJhoAx7
DjzvG10xc2Eqi99wbdMrY4mqA897NA77P5wHYwVoll4NQ2aTsbNdiJAPxkyCP63D
x3Iq856ytNkrz5iCiQxVVXaRn7BC5OWC/zDmEwRFUvGwAzK6zj7KuNSs1JuS1knz
D1eqbHXjQSfBjPJmeAusut0EewHYm/Eoi/BiIlNyoik9fgYSfoLkiqXjnQHk1Xom
KwRtWclfJDoeFNInJ+rArzkCAwEAAaNxMG8wFAYDVR0RBA0wC4IJei5leGFtcGxl
MAsGA1UdDwQEAwIHgDAdBgNVHQ4EFgQUI+05aminFOsYF9emXNdQ2t32jWQwHwYD
VR0jBBgwFoAUp5HUHJuWUkFXfPvKWN7YvCamqAwwCgYEKgMEBQQCBQAwDQYJKoZI
hvcNAQELBQADggEBACHLbCuw2Ijg6D7DGHrVZEIzc/sLibMaPFTm7oxRGT8f3jQJ
++Gta08ak0NcagGHf3ZiKJm1ibT4D7vMChkB45UwgHD4W+lGjBRw2ovgAeYJsMXz
qaLQtulwaCaSDkf5wXbiNMVfaH584CTFiVv0B13dyhcx+IM657yrqdvokueqdI3Q
gUm1wKQbs3F+8Z+pMwEQUCn0MZcjaoDJGDAg0Su2I8WDk5KBm3d8RJEuO/P4TUrV
94xfZry41wxENPyCQcKatA5Di+Jj8ui5+7BZLCI0kkKIlgLHnYsJA+uVhmrYoXf1
4r6r5C30gPl8BVAYcA9MaMZJqptD50D5yQ5gZtY=
-----END CERTIFICATE-----
""",
"n-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIB/zANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdFUyBS
b290MB4XDTI2MTAzMTE2MjAwM1oXDTI3MTAzMTE2MjAwM1owGjEYMBYGA1UEAwwP
TmVnIFNlcmlhbCBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
u9a7TgTbU8LCZNVXHYuaRplLcTWN+LeMPdSG9KMQopk0vGfhX7cUtro/dGUpJ/iG
13edJxjMQNlgE3J12RdzXA+bPMSH0JTyW3MIaT7NLccQj+rGBcUB4RttNQf9BGHy
RrmwayLlwyIElZpZceng04UE2f95WVrHkIbdg5hNbT8A5HR3OqWTq0g4wORCk3HF
/UImCAlfiogMBZzlUVeZCYhzMeupYzfkkdHoE9acRHK/mca3Wd2PKAeFc5aocFOP
jufHX3CFgxRBcvecnk2QV7J6GvzvBFQzvdy4H2l6TenkYohAZfvLJ1qOqbGvVOk1
mVlAsNeQ+ACUST5jEB5p4QIDAQABo3EwbzAUBgNVHREEDTALggluLmV4YW1wbGUw
CwYDVR0PBAQDAgeAMB0GA1UdDgQWBBTwyXFxdBgNsnpItF5ZvHri/3PYfjAfBgNV
HSMEGDAWgBSnkdQcm5ZSQVd8+8pY3ti8JqaoDDAKBgQqAwQFBAIFADANBgkqhkiG
9w0BAQsFAAOCAQEAPZyMUFk7YkYn6IDPbFIIrC8/c1bDeM74qeEz5RpFchEVED0M
fYr6CdK5JlqnoCzm2uVITMuizPs/VWSh/6afuF/HPfyO+lJjGvNassYtodC9Vu4W
tCqWIUm6Xbe2BoDpFbtOm8P7yYjVodiJbFwLXWfMwuy9NbpiFys+bcwnv11+bf02
srSjFHT/dM0LTyrneXpnAev5W9tVk4AjWV5MLPDaaD9lEUDIsbXk13EEZEsAhom2
rWXGLV6snqPEVWXCRY5kcNxI/8F5dLVIwzCySnaGJmkr6hgaVK0o3vEbIowRDuKF
96Y48bPkAo9QoJMzdcnbabLkFEntK4oLg8g8VA==
-----END CERTIFICATE-----
""",
"m-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIrESIzRFVmd4iZABEiM0RVZneImQARIjNEVWZ3iJkAESIz
RFVmd4iZABEiMzANBgkqhkiG9w0BAQsFADASMRAwDgYDVQQDDAdFUyBSb290MB4X
DTI2MTAzMTE2MjAwNVoXDTI3MTAzMTE2MjAwNVowGjEYMBYGA1UEAwwPQmlnIFNl
cmlhbCBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjPEtXw5p
9opVpxvdzcZDFaoDHVxPF9XvJfaK228+259cRgBWON9VWzu+oy5Sh2rtJzj88dHt
hiY5teuNq2Y1kxgaFf2knO1SHZXUwgEjK0XfTgSkWcOB9AmFQG90yuSLFczYmCtJ
2GGrZESFM0Qx9uCw/htC7l7rdMsJUfrS/El3UuE1AFxrAwsQM6mbHXM4spgZTMjD
g+iIDL391lLdvklbGUoO4dQc30UJinX4m2ST8xTfUD/3x7bi+ESZ5JAWz+YAK3OO
q628GAzL8YC0EvxhPfR9kGb8BdR7rjb5bYlSQJUh6Qg3dRmkwIXTJnkXGKce4Qi5
WtCgydjgK1rVqQIDAQABo3EwbzAUBgNVHREEDTALggltLmV4YW1wbGUwCwYDVR0P
BAQDAgeAMB0GA1UdDgQWBBTsgDCDJAioGLIU0uEjyNhyey7oHTAfBgNVHSMEGDAW
gBSnkdQcm5ZSQVd8+8pY3ti8JqaoDDAKBgQqAwQFBAIFADANBgkqhkiG9w0BAQsF
AAOCAQEAlDQsumUPGllgA+gj/8P7tseRCXr6gzHfhxRJEhJyb3ndNw7nq5ihxtOm
/iMCI0clO5w6uk0NLaCWD/aLuMDdLVft0Wa8XuGBoTSaW0NY/tg6T0wVhodzrfDr
PTd8drNL5dncWepQI79Af+WC060qQ0H/Ovh+YTRp4cGs2OAGKm7d8Mdzh8T4PISp
80J0k2WEAKpKDMJP+556AUoRcZ7GVPeQvOBL2NFB5e5ltFdAUakx1mSSCDKoY1or
CMVQGfTFndXtjkAjK5j4dtSZawIYa59At38PdS7IKfQvruG6lt09R7Yo8e98Yfrl
j0Yd0wesHN7XhHD3q6UTY/bzynWxlA==
-----END CERTIFICATE-----
""",
"mg1" to """
-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIUMUif9bkuk5DcHKu2PZQOeHS562wwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHTUcgUm9vdDAeFw0yNjEwMzExNjIwMDdaFw0zNjEwMjgx
NjIwMDdaMBIxEDAOBgNVBAMMB01HIFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDEhfCHpfPpDa9Y1XDhTWeDDSIpJeosGQoivurjQjlRn7sc6N+y
Ko18NEBy7Yn+gMkPc1au6lYuqV59+ko0LjJciuerBZw839j0XJk8e4P9esoM6nkE
OmqVVx7gzUctfwqvrweH8T07ZjTLS8c8fiuwd3KW8pO6d901RqH+ibMxqmhex9Vs
FeneBW8nBVy5Tph2ig/CAw6i58QLvYf4XMYwPuAulrNNBXgKkAriI1MSnVibzmWU
/eEk+jVvdtxgSGWePCE9VzEQadGkMaiZqYPBjQiBnL8gxqx/eb72qJHnBgA+PAsa
8Y9eMnAL72esosneFM9a7/UCqwfyuhJo9ZQxAgMBAAGjQjBAMB0GA1UdDgQWBBRj
M5Mp6NTQG62WiQtvgFmWU1qfzjAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDANBgkqhkiG9w0BAQsFAAOCAQEANs5EJfjnnRhmzvLjuAgsXsO+9tPz0TvN
YBEIOaxVsdicE51ZF4jeB6Ps496/oM/ewoBXS9Hg4x4h1BNNfJOFcbsaN9jqfStT
QF/OUpFS9FN0f51sl8MZn41uTTYmwL7zedy6+t5c+1/Yjst1DeozYgegHVBhncbZ
b+Qz4cUGpuH44fTmpLwaU0YLrpyPnzT+Vd2NN+nF7x8syCPybT5uLSGS6UYOsBLV
TrJMkh5X9d5Z2VFcAhejmZPNADgX7vXuOhWweYHpRsRwrjKcUHV6jtpm2UbBb+GP
rtAr48WVYCRnj4ahYSCDUlgxLZDSrj++Dxrf8X3nDZy6ndJRxuvb7Q==
-----END CERTIFICATE-----
""",
"mg-mid" to """
-----BEGIN CERTIFICATE-----
MIIDQjCCAiqgAwIBAgIUe1aVHEpN/cjgrOFrPETE1eFRL2cwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHTUcgUm9vdDAeFw0yNjEwMzExNjIwMDdaFw0zNjEwMjgx
NjIwMDdaMBExDzANBgNVBAMMBk1HIE1pZDCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANporrqFeggwrCxpFRnorOh+9aWFW0c+ohb2gT9qvazt8XuZXcSK
cy/4IZolXpAWXTrCQnOMPMYjzH4rxTbkUTNOJjEqwNRQ2Yib6Et25wN4JqpXYxrH
Dzmu0sa4ik1XjL7u00ZLoCNFaPNS9zIYXSbvSkbkLSbFd2Or6L7qBv+iSx25LMYe
fDIzeUq2bhMJh1W0BM14eLU2rDXMGFSPiBK0/v0SVNA6RLPtvgy2rilPo1jqAsEg
oGSGLiaVoEgxqqfUTxskl9uawKm1xOCqJlJJDHjJmHTFJiiAWqNRc5kDfcIf7pXM
tpf5E47u8eT589GxLNjli0I5W4wqbbQ2M/0CAwEAAaOBkDCBjTAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwICBDAdBgNVHQ4EFgQUwj1Huujx16geNqaQkR8p
sliNWmAwHwYDVR0jBBgwFoAUYzOTKejU0ButlokLb4BZllNan84wKgYDVR0eAQH/
BCAwHqAcMAyCCi5hLmV4YW1wbGUwDIIKLmIuZXhhbXBsZTANBgkqhkiG9w0BAQsF
AAOCAQEAfPcfdQLUt7zccmMIU1Xx62IZFDbTNCeOgm27jvoVayxqD/kbwY9Lvh1S
ih4s2I9HlsvurgxhVnpBhM5bCIDM5HL66pSP69p07+w2fC6YgICci8YvTPGtasUF
byMyYSAp68zaOHpaj0Y9AATbQ0Ezq1A7uIR+hxIXCSphjVUiMB08rHVKo/qeH0sM
Puq08xSRt7RYbCtv4CpGfR27623MWSxJ9q1Kpb/5VbXDW2x8EdndwwjTsK+syxkb
+CZGGJloWhF2MT8Ii04ZCkK5H3usylRIv13jY3AkitB/E8rzRYSq41tHSoig96S4
8uqrIjm8y3nWUH9hiYBonj0Q+5NB7w==
-----END CERTIFICATE-----
""",
"mg-leaf" to """
-----BEGIN CERTIFICATE-----
MIIDGDCCAgCgAwIBAgIUbaRoy2GGNhvQTrOl0DQuWCIU7BkwDQYJKoZIhvcNAQEL
BQAwETEPMA0GA1UEAwwGTUcgTWlkMB4XDTI2MTAzMTE2MjAwN1oXDTI3MTAzMTE2
MjAwN1owEjEQMA4GA1UEAwwHTUcgTGVhZjCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBAKzE129lQMhHh6dmp8M0FoFLQYY/8Y7y9WbyjgySTgKEePKSf/o4
Iw5xVEBVVkXaYRegZE4dlLKY6gQ5RCO2cKdJUN2Aaa8ACkqehyGmm3wkI4BIHP05
Vseet/GmVJVBepd4x7P6tMxfQcJA31cSqUGJDpCfgl9lUriDwvP0VlonASfG38tJ
pv2NLy9nZmtRTVxqrmG5bV4aIPETI16PpSEAd73/41olq7I1qR6mlcMuZJprApwK
sw07NLzCQm95rsLRR/wQPO+8KGDV2w0sFIajzlcpNtf8HL9BMC/zrGGydGdt5QTK
GJlasx3uC47w6832gpYGc1kxUbmx9rrl4UUCAwEAAaNnMGUwFgYDVR0RBA8wDYIL
Yy5iLmV4YW1wbGUwCwYDVR0PBAQDAgeAMB0GA1UdDgQWBBSKPQFp2vm4lpZqpq3k
1M2eSd78SDAfBgNVHSMEGDAWgBTCPUe66PHXqB42ppCRHymyWI1aYDANBgkqhkiG
9w0BAQsFAAOCAQEAxJFP++xTGQy8wmdgd5VFRTihDVj5g6JR9JZ0Hn9I2zWgHzo7
r7ixfJfU0/H0olYnwh+RfnZdx7FxvSF7WaKxhw26Z9FUICGUHy42Qb18rGFa97Hj
6OwjwdSBwHV4OObAz3GiBoDu7x8ZzzfBoFRyRBFexBSY0aymAHFyme7cF3EDb4ky
ArCDS/dkHft/Rtq/XmMrdVdEQV97xz7P0jkh1ENwGahz2UITBr09RwjLnJQbfnYK
WuRZ8XbG/P/hMwK3h8t4mlpFj94FMFkx1EH/OooVwKn2vw4mLru989pS1uZU8axg
UpBsmh60Qyx7A71iceEyOuwUVwTsMY6erC6Bjw==
-----END CERTIFICATE-----
""",
"nc-ca" to """
-----BEGIN CERTIFICATE-----
MIIC9DCCAdygAwIBAgIUK1qVnD/wtZMAHQbMIzi7fuCc7lQwDQYJKoZIhvcNAQEL
BQAwEjEQMA4GA1UEAwwHTkMgUm9vdDAeFw0yNjEwMzExNjE4MTRaFw0zNjEwMjgx
NjE4MTRaMBIxEDAOBgNVBAMMB05DIFJvb3QwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQDFNzHe38sWjboS/ejdzaEsbNq+08aFjpm72qJpSNMjFkpIEHBC
uSJpvmMthEOBxD9Ppdh1h2S3r2Q2UFTitNGB6wmn4w1gEwE34TuGu1AC5bMZQth6
h1dsQVeMJR3p5CEc9U1zwCWAfkjmDP/8cxS79AFrU7Ba+cVBgSa3l22N6tENIZCM
BX9xL+TRGp/OZu4uJi5/Pqo7UstxABUFTfqwX6Rt6lz9agQ2bpXwHyrXWP7ztbLQ
0Nac4WRfp8FAVHQy+/KhI6+ERCb9lcO4ydpOFxOEbL7T3I9a74x+USArUQ+FnwFj
rocdcXA3TA1MWIH3MtJJ1XmAvO66UYEkYQOHAgMBAAGjQjBAMB0GA1UdDgQWBBQE
Z3DoioYpcIxUEbMCKV1iTV2cHDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQE
AwICBDANBgkqhkiG9w0BAQsFAAOCAQEAtstK2i2VL72tBXKrctis250MI2yGY48/
N4kHPtrmt/fIsKAp7S3Z/qL1EdDe2lYQ9T6pNS63sE9/1lBs3Z7UQDC4noPUdaVn
3lT5MfaZcVDb870BicjDu2VBa+PK50OM3MHZz1n5ABm00ruKXKSuPEqHy94CBXti
kRI3JvvJhC4wcF0huzHQKJ9ibQ7BjmgjlLdyGAYHnCrd4RpCXf0OK8jfVwZ6WKnq
TD+0vYhsP+kMiuXqLyFkZZe9Oe8ahujDbyfuFjQYgE8wNNMIAnSCyCSjoBf4svGl
sn/P+cbsLK8Uddio1iMkoceu98IKJcKoPj7NDoqjHJrgdFtRlsRY4g==
-----END CERTIFICATE-----
""",
    )

    private val cache = mutableMapOf<String, Certificate>()
    fun pem(name: String): String = pems.getValue(name)
    fun cached(name: String): Certificate = cache.getOrPut(name) { Certificate.decodeFromPem(pems.getValue(name)) }
}

