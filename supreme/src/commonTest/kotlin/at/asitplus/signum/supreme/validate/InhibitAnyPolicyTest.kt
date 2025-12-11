package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.validate.PolicyValidator
import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.testballoon.invoke
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

/**
 * PKITS 4.12 Inhibit Any Policy
 */
@OptIn(ExperimentalPkiApi::class)
val InhibitAnyPolicyTest by testSuite {

    val trustAnchorRootCertificate = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDRzCCAi+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowRTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExFTATBgNVBAMT\n" +
            "DFRydXN0IEFuY2hvcjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALmZ\n" +
            "UYkRR+DNRbmEJ4ITAhbNRDmqrNsJw97iLE7bpFeflDUoNcJrZPZbC208bG+g5M0A\n" +
            "TzV0vOqg88Ds1/FjFDK1oPItqsiDImJIq0xb/et5w72WNPxHVrcsr7Ap6DHfdwLp\n" +
            "NMncqtzX92hU/iGVHLE/w/OCWwAIIbTHaxdrGMUG7DkJJ6iI7mzqpcyPvyAAo9O3\n" +
            "SHjJr+uw5vSrHRretnV2un0bohvGslN64MY/UIiRnPFwd2gD76byDzoM1ioyLRCl\n" +
            "lfBJ5sRDz9xrUHNigTAUdlblb6yrnNtNJmkrROYvkh6sLETUh9EYh0Ar+94fZVXf\n" +
            "GVi57Sw7x1jyANTlA40CAwEAAaNCMEAwHQYDVR0OBBYEFOR9X9FclYYILAWuvnW2\n" +
            "ZafZXahmMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBAQCYoa9uR55KJTkpwyPihIgXHq7/Z8dx3qZlCJQwE5qQBZXIsf5e\n" +
            "C8Va/QjnTHOC4Gt4MwpnqqmoDqyqSW8pBVQgAUFAXqO91nLCQb4+/yfjiiNjzprp\n" +
            "xQlcqIZYjJSVtckH1IDWFLFeuGW+OgPPEFgN4hjU5YFIsE2r1i4+ixkeuorxxsK1\n" +
            "D/jYbVwQMXLqn1pjJttOPJwuA8+ho1f2c8FrKlqjHgOwxuHhsiGN6MKgs1baalpR\n" +
            "/lnNFCIpq+/+3cnhufDjvxMy5lg+cwgMCiGzCxn4n4dBMw41C+4KhNF7ZtKuKSZ1\n" +
            "eczztXD9NUkGUGw3LzpLDJazz3JhlZ/9pXzF\n" +
            "-----END CERTIFICATE-----\n"
    val trustAnchorRootCert = X509Certificate.decodeFromPem(trustAnchorRootCertificate).getOrThrow()
    val trustAnchor = TrustAnchor.Certificate(trustAnchorRootCert)
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor), allowIncludedTrustAnchor = false)

    val inhibitAnyPolicy0CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDqDCCApCgAwIBAgIBOzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNVBAMT\n" +
            "FGluaGliaXRBbnlQb2xpY3kwIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
            "CgKCAQEAwm7RmKNqzNVB1upuD/XDkNQZe330VuJCvAN9qtUbmOwBCQ2Imy3G22tO\n" +
            "o0g0sd0FlDusckPU2bfVW59Ya5SQXlfQq3Qu7dmr4SznXyLwjEFkJex3YFi/0RiL\n" +
            "dkzC/2ZK8ikQtU3HHznh8qImo5sb+STz5esh+nqtJy8+eWf+PzIRzVtGxxThnqCX\n" +
            "fwCOYcgALxcvZEyfGmZpKGjyVGNTmmLXYUHPOaMN84+sTueys3R4WaidErJQihOJ\n" +
            "I0D8k2zNiP44crr8QaBPDYujleFp99ZoL0p0t9rb/i91Oha1YR4AriZOkSdZ+12f\n" +
            "l4oYmUVSpiSr64wKFCFYOTybXDHr+wIDAQABo4GaMIGXMB8GA1UdIwQYMBaAFOR9\n" +
            "X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBQYoKB6av9qnYWCJM3DJoX4v4o3\n" +
            "BjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
            "EwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADANBgNVHTYBAf8EAwIBADANBgkqhkiG\n" +
            "9w0BAQsFAAOCAQEAYACyQ2xi2/hapopt7cI+wPFzJtn2eSzNP+lkyRkp8VbtFW6k\n" +
            "35IPAUnuS+bcB92Cn0LwwSXIzMJ6Cs2su9UmKox/psMXH8UMeebjL4WtpuzqtGLX\n" +
            "eFVo3Cmfdih0JICYo952u0Ugzw5LQzMMNDgtcSjlo+OP7ksOyvP9o1hKfk580cLV\n" +
            "X+PiJDmqGbnP+0ERDbN4pRQvYNGNFyzBgqGpiIENgWIJwc42HTHpaG63Y/tVc30M\n" +
            "3Gh3//ZomjVlWg12PLoYefV3xv2TT/uK4zb3ppeznSGso8sCYh+/p6/T6brIyqUh\n" +
            "a2yA6ge9SUPKy8EVgqo96s7ofQwobF5DOJ9UBA==\n" +
            "-----END CERTIFICATE-----"

    val inhibitAnyPolicy1CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDqDCCApCgAwIBAgIBPDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNVBAMT\n" +
            "FGluaGliaXRBbnlQb2xpY3kxIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
            "CgKCAQEA6zBvGZdcVEAf/5tkGFfFnBVSmugm+C88xlCv9nv6QizfRFE9unEgMgC0\n" +
            "XzUOeYBfsVDD+s8vjLW6l1oYd/8dB8nj7yPL+Zp8tjANb0Pm5Q5IH7tN+a/o81Jh\n" +
            "sb2bJky9jSiKxaFNhGHZ0uKsGYZn1im5XTmqAshVWF129drcizb7//FSTeAnkjpP\n" +
            "Qtb0UqQljSTeuXIdDUnWSuUvJHOzlK+wJBBBlxQQU9AFXyPSejLDLHEyVEgweQ2g\n" +
            "/PrEkxBpCl84BSeXw7hOyeqy8W8DCRlNH4vbi4UESM5nydgHbpi1WJg7XayRsv4L\n" +
            "YtSa424ueI3H2OG/lfY+6NlBJl1PewIDAQABo4GaMIGXMB8GA1UdIwQYMBaAFOR9\n" +
            "X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBTYpp4nlxHDjtQZIdcgvJztoXvy\n" +
            "0zAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
            "EwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADANBgNVHTYBAf8EAwIBATANBgkqhkiG\n" +
            "9w0BAQsFAAOCAQEANF4unXV7d2qUpPtdqy72XTM8e4g9dJGOS9XA1xRPjh4flZE/\n" +
            "7DPh86LuhfQALvGqlwUcjTY0ZTRq47YKUqj840+y2qyii4QYq/USs3TRqlBZVWYL\n" +
            "2gKOFDCGWl3MLtlFR4kgRmMpcHRxuE5fDHNdSBR/o9Ri7/9EIOjUA5UWjCYk7ccI\n" +
            "oHQ3vVkKspFSObgq23zJTsahW7s+mmxbwxDFQVyQ6K4jXOnemBodAIin7KQXSaPq\n" +
            "SPUOcOFTf0430xU+HZFahy8Oqe9PdAf1yrBiMMG4W59Bly0cJsFdvEgQVDu+h1S4\n" +
            "gfrQDgV76wl1nblJHH8uFYRFdYG99/Z45bjIVg==\n" +
            "-----END CERTIFICATE-----"

    val inhibitAnyPolicy1subCA1Cert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDjzCCAnegAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
            "dEFueVBvbGljeTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBR\n" +
            "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEh\n" +
            "MB8GA1UEAxMYaW5oaWJpdEFueVBvbGljeTEgc3ViQ0ExMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEAyVwAGmULZXHVZpOzaNmYz6rXZSAplQb+QtuN41pU\n" +
            "qvxd3RpiryOIZXMfSyamdM0tvo5Vfngen/IjnrYpWfPGBh8oZtUI26TXLYpaGTGv\n" +
            "9bXynCNNRcLzlmufhCFvgipDcQlCB9KFBgBFX0MXSOgf4MviSOncnVm3vIvrUR9/\n" +
            "xUGRmxLMb3FJyiY7MBoGAUxbsyEVA/sjn2RquDHLBu83hCnkCX0WuSwyz1rQ1KT0\n" +
            "kOauGVz0Zxj+wFwpSz4jTdazBXgDEjFwqptRoivzyXz4jwldMEB75XyjIMV5yObu\n" +
            "Lvore59mbwDtqsSaOsTqjXXlqW0F17DORMSaYT/CHRugGQIDAQABo3YwdDAfBgNV\n" +
            "HSMEGDAWgBTYpp4nlxHDjtQZIdcgvJztoXvy0zAdBgNVHQ4EFgQUdKDVWNkrU9Ir\n" +
            "sM1dccahv0OnyBUwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wEQYD\n" +
            "VR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBCwUAA4IBAQBnzM+7R73vitIVn6v1\n" +
            "RdMLwiGv+PRyshDNyrzeAIGRmQxSto06y93imt4X1l0WuwymoO3pkRJP34x7hqwB\n" +
            "PZfufX56zLc/TndMmLNRrjUgmQZV5MdADqMQwMWM8TjxLlqhKD9CAb7Su6PlsJFx\n" +
            "eosv8QTJti2dBLAGrmMoqnf8om/yqBE1Ix31rwhB8WhSvYd7LkMdlJWW5Eu3IqOj\n" +
            "OGbIa4lm24r/g7mSktFTrZMa9uCjaFhdMl91qmHjuMVm/8Ze0STx18SyUse0qBre\n" +
            "Hizk6JC/+JHciyBn/+ioqYagRGyfCcIlqw0hSH4ebejtEt+tZHvUWN5lmjkzSVnR\n" +
            "6kIb\n" +
            "-----END CERTIFICATE-----"

    val inhibitAnyPolicy1SelfIssuedCACAert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDkTCCAnmgAwIBAgIBAzANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
            "dEFueVBvbGljeTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBN\n" +
            "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEd\n" +
            "MBsGA1UEAxMUaW5oaWJpdEFueVBvbGljeTEgQ0EwggEiMA0GCSqGSIb3DQEBAQUA\n" +
            "A4IBDwAwggEKAoIBAQDCFu0fJxTpvoal9t+mW/X3OsIz61KWZdMukGwyZ2qGnOVp\n" +
            "JtzZowwep2J/vOZyyAS3eCLJ+DE5rtrCUFnlkYbD0aRM5Ov3LQv6/wVeASJ2peE1\n" +
            "ktUPdTn+O2smk0gkTqrE0wQCB3VqkpoeU6MGkfVRi5cmuuX9yH9DrfNDqBt0v0qN\n" +
            "k6RV1Qatllw9vMcmzPSFw5QtF+siYKvh0Y9ZxR4LpleoNgNu0WDEiGSObwOcWaqn\n" +
            "kdtki0sDY2Rrh7l7P7AmNILg2SPd/U/999Eq4U9s0qDbWRm6JieFQk56kSTqzSFs\n" +
            "VqNknWKkDddew/YGC3HgkMGDlZqGXjqCOdYNjylZAgMBAAGjfDB6MB8GA1UdIwQY\n" +
            "MBaAFNimnieXEcOO1Bkh1yC8nO2he/LTMB0GA1UdDgQWBBRAqcjvsmE0lURsYYYC\n" +
            "qQ/mQa5fxjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATAB\n" +
            "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAHYPM2xLE6+X6y4j\n" +
            "OiVLbySiZbkfMcMa+/9NQGIq0PAn88BGxaX13t5xfcGnUSkRJ5cBJN8HIEOnSXi0\n" +
            "8SzRDMOIlMsBfsOLWPrrw3WAmRI6kAbqAjgwYyfvVJaAXD3UotQHsBSbuE9wOo5D\n" +
            "HCZmSB7GAscnCMZwjz0ZVfu9Efpldi4PmoTC0Z6URop6n4N7w4IviZlSfadQP0O+\n" +
            "CTZQHt/D0HRiGgF+DiQ/4mSWgP5wBlhhUJE0pwVLCd92PfMIqsK5cSgN+ILMjlX/\n" +
            "rKeu95Jro38CL9eXpEPnkECq30jAMZcBqAigQ4GN5sAw0nT9Oly+GjV1P8Bu06zg\n" +
            "hTJyzDE=\n" +
            "-----END CERTIFICATE-----"

    val inhibitAnyPolicy1subCA2CAert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDjzCCAnegAwIBAgIBBDANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
            "dEFueVBvbGljeTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBR\n" +
            "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEh\n" +
            "MB8GA1UEAxMYaW5oaWJpdEFueVBvbGljeTEgc3ViQ0EyMIIBIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAQ8AMIIBCgKCAQEA1wKZbiE/ysToa9HAVzFhiFhUj8zx2fLR4Sx+Yk5p\n" +
            "0N2lfDWP91hTtP6CamBOzUIRH8s14bRvcAJfwdepbzDw/SzH2gi9D3qlGA5H6Sba\n" +
            "29u5CHN1fvHcHkBh2uaA0r1tGUgI5B9OG3/kGvzWN4kU5AY3zsZrsxASmbyzUtbb\n" +
            "GPQGf+UFrzFVnTzSTo5bfhJI+J3KQOe6TpusxlnUsKbEMEAItF1IqIKl/9LskeD4\n" +
            "Nb5Rr9BjPe73Q5mGqtd9wV0gZNMa2wpnN2mJtdpJc9E4c459Svdr0ud/Lx9CMm2t\n" +
            "4TvBjaDnhemVQ5PnjTUtIWsX+bvLmLMyUpPSPmJJNfx0EQIDAQABo3YwdDAfBgNV\n" +
            "HSMEGDAWgBRAqcjvsmE0lURsYYYCqQ/mQa5fxjAdBgNVHQ4EFgQUjAXc335k22K+\n" +
            "20tRZIxqZthco6MwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wEQYD\n" +
            "VR0gBAowCDAGBgRVHSAAMA0GCSqGSIb3DQEBCwUAA4IBAQBVZuMq6323Ai0EJicg\n" +
            "9wk4pPvFWNdG8kkAEr6jA6lrr/h/iKt1WbQnRRMHNMjfQa11Du0EiQpdrb+lHmb5\n" +
            "PwXAcBBXJf5L6Kb59tR/bvnEbXWi4GwQeVlPMmyytl2Ry5h0GahTtCPdFL0VBD8L\n" +
            "4w7GUL3KTjJp4/rOm42Dnk8/RlpYwia6Ynoup7xOKOYJR0f4ooIYmQs4eA9eMSdj\n" +
            "VVVViwHZqTzshR2D9peuGRj18go3tVJj0j2rrsC4WJ1fVhlpO4UGmZZvh2MO8UJI\n" +
            "U8NSOizyKZu+RvVHr0vXJJCkmShqYKTpbg4mrRGY5VjvEwSZU4wN00zZ7gNd5O/v\n" +
            "vKwW\n" +
            "-----END CERTIFICATE-----"

    "Invalid inhibitAnyPolicy Test1" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
                "dEFueVBvbGljeTAgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBm\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTE2\n" +
                "MDQGA1UEAxMtSW52YWxpZCBpbmhpYml0QW55UG9saWN5IEVFIENlcnRpZmljYXRl\n" +
                "IFRlc3QxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNW1wTtifNXg\n" +
                "S/7/6OTB9nSbSKSw2BLiidrM8x0nGdCwUY++tWaryTAV6tJVLmfDOSrlcqgNgubo\n" +
                "U2ufM/4Kxrkt4I7I8V7GIuXMVSOSG9DjroelJDTfv/PKfxd/Eb+6mV0lrfempURc\n" +
                "27X5CfAfKmM22sCPohtfBzKwjsi22RA5dZ6nlUygOhrJgvz3D7/3Gzrrnt+fEtye\n" +
                "USyq+8nR/zXX+JbOi9gC2WsZMvyRb7pR5+9Lu/qQjXQldZaY+trrEfUmLRUmrxUZ\n" +
                "CwFjs3eV+vObbmsXnORZWwuTPhw/GBMx227uefpgnZ6x1uJB+YEitiHX72MDkS4q\n" +
                "6I4Y8p3y2wIDAQABo2UwYzAfBgNVHSMEGDAWgBQYoKB6av9qnYWCJM3DJoX4v4o3\n" +
                "BjAdBgNVHQ4EFgQUBKSzfwBnruEoSD6YjRYo9lI4/ZcwDgYDVR0PAQH/BAQDAgTw\n" +
                "MBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEARGD3khHtk07o\n" +
                "014aVan3Tjr0c4mX7zn4cgm4Vgep+/DOtUEcV44m13/YZ4KjUXR9zaHc8OQhOZW2\n" +
                "oWCAaEyL0Qw4im0m5LVWkKhlomLU4TJPT34u6m2xlURUwmcUkAaaKf4Jpy949zH6\n" +
                "x5SFLFB0VCWUgsxSgIgTI0cdl1gnd8WE5nsc3yUKbC/1HRscx0RgjH3y0UFE85FC\n" +
                "fkcICoA6prUdt2Q328dRd+mY82AI0/lD4Amr1gvbyUC1M0znxTsCZPNHRPQDVqbx\n" +
                "rQLcUDlh4004RiOEkfPyvm4OsfTD8df7euRyegy/gPde/vipEYQP4bARJalAC+ae\n" +
                "/U1rEo3zNA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy0CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)
        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Valid inhibitAnyPolicy Test2" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnzCCAoegAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
                "dEFueVBvbGljeTAgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBk\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTE0\n" +
                "MDIGA1UEAxMrVmFsaWQgaW5oaWJpdEFueVBvbGljeSBFRSBDZXJ0aWZpY2F0ZSBU\n" +
                "ZXN0MjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMvWJ2NltVcIqG8R\n" +
                "Gd6aAaTkV74OHh22qqq5VisygSWOraY+e/kZzgnHexceST9oUvWxJ210DYysc8E8\n" +
                "NQsMEQRhJiy0vK2Pweb2q2Uv/DPpelT9Gzx3CuEuxvUvOY7EMYqsTkWkcvCbxJ0i\n" +
                "/fYxmUJgsb+tdWuggcp1DV6UR1YVZFwFuzwFR6U3NxhkSKh1Aqpeg3rvO9igxaIe\n" +
                "1KWuNKXb8GsQREEKOxXdRK21wrm7TSq4uhpyTbHb2GjhtAAKb/fiOtfWjibEhANg\n" +
                "Xd9kxjSYI4npbisd+yYo45gXEDoqFTtxz6YPtR7+dzgVKxOE/Xc+PtXIl/0AT60Q\n" +
                "Rdqsz/MCAwEAAaNzMHEwHwYDVR0jBBgwFoAUGKCgemr/ap2FgiTNwyaF+L+KNwYw\n" +
                "HQYDVR0OBBYEFM7BJgyfyIp3q6sZiSd0E+VdkSzKMA4GA1UdDwEB/wQEAwIE8DAf\n" +
                "BgNVHSAEGDAWMAYGBFUdIAAwDAYKYIZIAWUDAgEwATANBgkqhkiG9w0BAQsFAAOC\n" +
                "AQEAn87EWhrmPNMFRrFS2VTSXUb/3OPnx1eLB918Vo+KY5fwcDGO8WuhxFsszju0\n" +
                "BShfZnrwj7/Hrc/UdmPbk6RrPq5BMsmpLMwiqpxjqqN7J5C81cXvK2f7V4UX8sVc\n" +
                "OriHWK8Vt6dEk0CN6Rt2AkkUE+7LrOS92hhLU5Opzyue3ZW6JPLfuk0uER2hKt3r\n" +
                "POm96ZMVxNH0QAmZUQK03IqzGr+UigLgQA78Kc7qOYqTVc9JGuwu0F+e25h0L83W\n" +
                "xRYW+BjGWRUfL7Y0uwylS772ZWLNBRac2mrniZJZNIzzr92Bwt5R4w0ZR6cB+C/S\n" +
                "qN7XKYDdE6V9nwrJt5Wum031lw==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy0CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true
    }

    "inhibitAnyPolicy Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlTCCAn2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0ExMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowXjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExLjAsBgNVBAMTJWluaGliaXRBbnlQb2xpY3kgRUUgQ2VydGlmaWNhdGUgVGVz\n" +
                "dDMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDXXPnjv8RRkKcKkZOV\n" +
                "yGORDonJuI1SMrxuX02bYLRAC/XwvLOJpDsf/xA8JLffgaFLY6qfYmBeyVrpPvTk\n" +
                "wyLD5LwI3MK6sc/lTCIBidoDBodfodpzBTQIa4MJLElXJRCkwyuEVMAFNng8N4Uj\n" +
                "6ZGlBUw5t0wX2dudQQaILmmKKq01ChpP0DCujvs2vcadAm/sM3mpOoVrmc5onF94\n" +
                "szwB1QrNrLrPN+WlaX67dl/m/uuK4Bbvj1cWOdyAtpskVKl4uZoyTE4gyuOSRbFX\n" +
                "H2jC1XMd2yhtePKFYkHjEQEITpSKy/FPeQMyw9rzFI7t2+nAqP090pB4YsLNPYgN\n" +
                "cG2HAgMBAAGjazBpMB8GA1UdIwQYMBaAFHSg1VjZK1PSK7DNXXHGob9Dp8gVMB0G\n" +
                "A1UdDgQWBBSgPl5tKwvtC+NPQQGd8WO1AN3BkjAOBgNVHQ8BAf8EBAMCBPAwFwYD\n" +
                "VR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQDFsWjMxFvi\n" +
                "8SyiT+A6KlMhtL6UINksICnrb2ozC7mouE1uge+XdzRhk6ub/x3Yrc83OxZbtZzA\n" +
                "f36G5OSyKn42LPAtsqW+X98xJJR4ADEsAxUTiodITJ0O7rolRFurlCrITR/AEswp\n" +
                "bGyspXbSZVpCMqr87BCRlJxklpk8Vx4JevroJBrbvqtm0s7W1RsaazNzZyA30WIA\n" +
                "SYISAcXhLlJhA+XTVZVMp7U/8RQ7K8lftW17ZJ1AQGc1KTSHhzOeZeoAJCYaqBLz\n" +
                "BTRFRv04CGjhGq3UCBDazX2XfBQRg4TIoTo2GE2/cpv5oOMFZuxJLESCZbbev2Df\n" +
                "8JFIDAsJaKox\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        var result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true

        val context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), allowIncludedTrustAnchor = false, anyPolicyInhibited = true)
        result = chain.validate(context)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Invalid inhibitAnyPolicy Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDlzCCAn+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0ExMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowZjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExNjA0BgNVBAMTLUludmFsaWQgaW5oaWJpdEFueVBvbGljeSBFRSBDZXJ0aWZp\n" +
                "Y2F0ZSBUZXN0NDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKOzb2us\n" +
                "Rap/gcyEbEwwK0iXF70rX0khyal5XsZa1RjAWbLF+wifYFR/Y1Pee1seu+5+Y9d5\n" +
                "Y6OlpDWYZd81RunoYs10UNfSC+MdbLEJrqKsX9Ol/iDg3PaGnsHHqJPkPpnZgCxM\n" +
                "9KgV3SxPXgg9UzDeFgNs142NbrFeCUjtU4s6Z3h4CRNUG08DTB06aq5c5PWnNJDo\n" +
                "HGXkssX6+seFinJZC1S4og/wJOclr0g3+6rBw6aftcvQgsUMl1aeLe6adl9yLuYt\n" +
                "HMopbU0wbgiGeNyjs/Z1/sZZ52xrsGCt6iUMZ6i+EAEoqCrwhNMG/zRUSDyXN3m4\n" +
                "9lZCX4HJh9VGHxMCAwEAAaNlMGMwHwYDVR0jBBgwFoAUdKDVWNkrU9IrsM1dccah\n" +
                "v0OnyBUwHQYDVR0OBBYEFBIkx7AI9TiDfo2NT4HTCl44Z0KyMA4GA1UdDwEB/wQE\n" +
                "AwIE8DARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAHhbECZV\n" +
                "VvZ3I4PTD5AZubZbJlT4CrJXvqc02fLFqiG5/n/XsEwIBAPBiHw+ni6N/10w9Sl1\n" +
                "SZxkONAMLx688plmbZl1sq+uWVLo7Zn8oLte1ka5di5YteBL3Q9xgxTiT/n5gLip\n" +
                "AamIJ2+Sconm6lw/ox2Bwk9GvQ1V9BhTCXZYpA636a2qwhgsgypHcvBtxxo5dpAH\n" +
                "76B1+opjDl90vtMmOLYZ3DDmE05SdQOW3hu3FyOZWlo9hveSKp1jCpI9YTBh5xs7\n" +
                "YtziLdcidNDuWF5qCrkAfJKn2bVIgWCV6QUGsa68tMzM2tX9PDEIulsjIrEy7TDE\n" +
                "TWdj2tcah6t6zqQ=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA1Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Invalid inhibitAnyPolicy Test5" {
        val inhibitAnyPolicy5CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqDCCApCgAwIBAgIBPTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTTELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNVBAMT\n" +
                "FGluaGliaXRBbnlQb2xpY3k1IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
                "CgKCAQEA3UgNJ6YbK+6YWKAVLudNC4/A9551Bu01IOogUe+0F9LIv7bQPx7ovDiZ\n" +
                "HA5j7bO3vR1i/VHFgMxrurBmyWXZIK5fYUIqZd5m5ZCZCXPeExOgIL9XrZw0rt6x\n" +
                "4eZHWN2ygIALlicLJvLXNIymuypS01Pca90e0yumWg3yV4HXrK484mV4xAXvkKNb\n" +
                "gD6wdSQ76tsMG+XnE7doGfAIXPZS8jwkwPhxNCcgmmUoHVl1aeWlJJmtTkPx6Dpq\n" +
                "iysJMyA/pfWGb4f6PRMI8Mv6cN+2rfwV2Ec0v7W7KV/moSLJ7u1zqtHEceTE5F0V\n" +
                "wbIsnv3b3kLV8Ey3yMQihZcLx795ZQIDAQABo4GaMIGXMB8GA1UdIwQYMBaAFOR9\n" +
                "X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBTAJoHnadadfPC91Z2qUw5l+ZzL\n" +
                "CjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
                "EwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADANBgNVHTYBAf8EAwIBBTANBgkqhkiG\n" +
                "9w0BAQsFAAOCAQEAhs7mMDiz1F1wTXNxIBHbOCsg3foXn4M6jK6pOzfDLo/VQG0G\n" +
                "fvIexIWEJllgQ4WDg9egg+MKKbHRNjDnSZG/nDfxJzWf+uvZ/AtaU/d7CuFb6ykB\n" +
                "2kYoowmyRZY8cOLFHIMgIyXlOtaelVyvrgmz5deKSBO/Tp5/ss+84UUtbwHv6RL0\n" +
                "jhgau96YAShZiwvDMCDDnjszHCH0Rl+qY9SHGcuQgrAzj8wYyCcJ4PZDahDxZoxc\n" +
                "gB/0yUMXG1XgLFK49LH9e18ya3aZ3St9SHa9kkm7l6zqymyR8q4EBgK5jZEXy2m/\n" +
                "thrfDzQan/S/tIrqzJHovMR3/AXkI21iCTSQKQ==\n" +
                "-----END CERTIFICATE-----"

        val inhibitAnyPolicy5subCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpTCCAo2gAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
                "dEFueVBvbGljeTUgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBQ\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEg\n" +
                "MB4GA1UEAxMXaW5oaWJpdEFueVBvbGljeTUgc3ViQ0EwggEiMA0GCSqGSIb3DQEB\n" +
                "AQUAA4IBDwAwggEKAoIBAQC5561W3C1C2WjmuY6Gs3Vb32L4i2f87Awffxn7zLAm\n" +
                "8k85fRXHKT2gR2DKwSM/mNt4q/22qcjAKAuEhv7GZ2glmOt6m4xeYUq+6Y96Qi7Q\n" +
                "Vq7jwBxT+yIuo0GdCsnSVJ9ZwS4pFlLMeL0zMZQniHRYg28fcEp/DJZpjxMu55DN\n" +
                "rNm7+nEwphnSxLcuNvq5WO40rKBDLKVEOOopp3Ok+bsamuVWDkucqrkTRmEis3Wq\n" +
                "XXv0Jgsh64h9SCI+0bjewjlQppunKfj0upZCNTZGodWKf5qNuEcJcVQPJdT2/vfk\n" +
                "m/GaTflkY7yGkc2Vr0tAJXkiS6wk1lrGKMLIzQzSbVzbAgMBAAGjgYwwgYkwHwYD\n" +
                "VR0jBBgwFoAUwCaB52nWnXzwvdWdqlMOZfmcywowHQYDVR0OBBYEFGyZqbYF675w\n" +
                "STZMWJoi6BSIhS/bMA4GA1UdDwEB/wQEAwIBBjAXBgNVHSAEEDAOMAwGCmCGSAFl\n" +
                "AwIBMAEwDwYDVR0TAQH/BAUwAwEB/zANBgNVHTYBAf8EAwIBATANBgkqhkiG9w0B\n" +
                "AQsFAAOCAQEAd5CGkdrpbMYK6NXgbS03kQFxAhmgnpY6aU2j7d4RatvkkSVHp5Nf\n" +
                "DzooyQ9oyz3cmfX5c73vN+Ugxqst+lc4/wjnNmiCm/bLj1pQ89wdORHKgiLU2HnL\n" +
                "aTkQQOwSczl8xqhK7ATk0ZgICmMwxMxhcen90u4SJwRPp0dIGfIiBUEvnnst5Lpu\n" +
                "9EaPAHYvrsXn1kYKylWEFRoGEI20TJ360COTYF6TwFR+hsfkcIYL2CewtkhqW0vc\n" +
                "k83ZgqIlbI7mTScbLLjVjFbldjJ3OGspaXlWcVPAEP9T41Xj+vOKagDwBxM1gaOJ\n" +
                "h8Y4uEIFS2eAY5+qzzXEnbTG4gVCEJzyTA==\n" +
                "-----END CERTIFICATE-----"

        val inhibitAnyPolicy5subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXaW5oaWJp\n" +
                "dEFueVBvbGljeTUgc3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBTMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEjMCEGA1UEAxMaaW5oaWJpdEFueVBvbGljeTUgc3Vic3ViQ0EwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDCRGX+IdLeXlu6WOO1XhgOgGqd9vt8vGh9\n" +
                "kaeJkJvY+1hpPPj5UzXz125tovx5oIsnxll0/M76mJUpNz67W/qeg+FkBHa7q+ct\n" +
                "oZefLzysWBF6v1SkRZckKujdjCLHw6qoxSbuOKRC3+Y/o33dkB9wCcAjxWC1SZAh\n" +
                "AK7E2PkfSh5pPE9waAUQTO3CjJuUPPwffh3WFV52ahhR18RfEMJPsIFQc9b40hEl\n" +
                "kz4vuZLkT4BP/HIuFIMF5uzehcUGs4DUXQ0wxQesr+0AVCcDM5R1CR9S3WaGJURM\n" +
                "uCkiQ7WWefgvk2dYkAoE0f0mwMo7nXHpj0D0LFXCFSXlNS8uV0XlAgMBAAGjfDB6\n" +
                "MB8GA1UdIwQYMBaAFGyZqbYF675wSTZMWJoi6BSIhS/bMB0GA1UdDgQWBBQx4T/8\n" +
                "Ym6AZc2peRAAK26JWugFwzAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAFxP\n" +
                "sWa61v5gPCuZjV4CP5aoR9c3RwnXgwb1gigoeakbWE0hKy6HdZhrcpht+pSoeHOt\n" +
                "saYnIEm2lM7MOC4vzvtVMTe3vj/PTwx44yGK3IxSRYs3tWesciRAJdfJrIBxUpgO\n" +
                "vabTNdI2/7gi8KckWRLCpo0aiRriU8W0TDwMD9lEEMRJ2UGgbIsmExsy8h6ylWxN\n" +
                "7BAyMWoOx8EQe7Fh9b+j5t3A8XZ0Oe7LdT7NDS+UfFKFqoP21v6h7iXzusoHA3Uv\n" +
                "YQjEIwuZ7dYzDIXETb7jzQvdsY2mIFIwHtqP6csVtMQVu2WugApFjwGoNV5d1DMn\n" +
                "XpjK0TofQMZYNOxBEZY=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmTCCAoGgAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMaaW5oaWJp\n" +
                "dEFueVBvbGljeTUgc3Vic3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBmMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTE2MDQGA1UEAxMtSW52YWxpZCBpbmhpYml0QW55UG9saWN5IEVFIENlcnRp\n" +
                "ZmljYXRlIFRlc3Q1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA195F\n" +
                "jNz2GSpq6/NfJwsI1oWaPDb/TIRaMvsEhof4Du7/nnHZLHEKCHncySsw3S1wqAaf\n" +
                "gJCqFiOuUUQNc7KORn2p3OQjnQ6Rx+bqFTRFhUopVriqtIohLh14uvN30gZCwz4b\n" +
                "cw7uw2I5uEzPWVZjF6gnY3p+mVHCRR5+rp7glk0TIzOUDK8nvu9iUUPB88rRwlm4\n" +
                "4CwQZPMCnd7+3TEcX2Z53do2w7OStN/J28/tuEO7CMwYeOFZZ+Umy3xX6fD1GHTa\n" +
                "d3aeqdKGHpTs3UzKS55z++st87x9o/9SDMzDhzuiJv7eVtW5w/df8B6YCXZajDq0\n" +
                "D7pcygmL2EZsRbvpuwIDAQABo2UwYzAfBgNVHSMEGDAWgBQx4T/8Ym6AZc2peRAA\n" +
                "K26JWugFwzAdBgNVHQ4EFgQU7ezFAtleK5pOd1B3fpcAOhJ7b5QwDgYDVR0PAQH/\n" +
                "BAQDAgTwMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEALvsV\n" +
                "SM9/5C8mjAMEOnsUzL6HCXvgRuQ8nHmTEDTOThapesSndUMoJQMPlXlCbeRP1apB\n" +
                "zUsPuavZxi4DAmSs+xdge9QLVDbVzf6uC698FeHXKMoVs77HNKFQOpWATB9J+1OL\n" +
                "zgSzZYGdrFQyYl8rQFdrpXTguzMDKAbCcyQiSoSGr4zlHg2yJXUP/nxtgsDVqYfF\n" +
                "SIpduRdnil3dV5h9GH/74QIqBZC/9sKO6jVnxD0RbIc64nL35LoVlMFSke4UBS6Z\n" +
                "PmcQzvnfMtpK4Gi3v4H8btSpKstdIt+jgUpgz48xzejGlaRX5Ad0MNgNjFmN61ib\n" +
                "XANJSNmGQZWK4w1woQ==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy5CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy5subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitAnyPolicy5subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Invalid inhibitAnyPolicy Test6" {
        val inhibitAnyPolicy1subCAIAP5Cert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDqTCCApGgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUaW5oaWJp\n" +
                "dEFueVBvbGljeTEgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBU\n" +
                "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEk\n" +
                "MCIGA1UEAxMbaW5oaWJpdEFueVBvbGljeTEgc3ViQ0FJQVA1MIIBIjANBgkqhkiG\n" +
                "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu10Q/7dllIbdDlDoQXjb6LbdUZq9K1NJUZUZ\n" +
                "KxTwF+JnWroxFkmUtCYP/6sxI/yLWrD4uDuVWDx2bYZ1lGqdrBucimlvpUWAqJmu\n" +
                "jrChxpNXfzSBs/9uSsp9S5Y9ZCU7+lSVoQ0FPM1i1qaVC23crOxcKyVDwnotJHPi\n" +
                "eL4fU9zLnw2LZr3gcF5wn9cH1qXGYc4HKXm6MaL2P+RdtZORjBX4/zzbidsar91N\n" +
                "z18nDm8ittPS5oMPDGA7Et3pSp+6IrDn/r6kuGaLYrJ89BZ2rV/jQ4krDZiSPtE+\n" +
                "sjcZacvGu2P9WXv3ZY6tqo+125T1NzHPDNLiBcdnT/bLW24C9QIDAQABo4GMMIGJ\n" +
                "MB8GA1UdIwQYMBaAFNimnieXEcOO1Bkh1yC8nO2he/LTMB0GA1UdDgQWBBSJBFR0\n" +
                "BmCz9wBuoGGOFfu+UgIGJjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpg\n" +
                "hkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYDVR02AQH/BAMCAQUwDQYJKoZI\n" +
                "hvcNAQELBQADggEBACLLLvFs4MAJ9pQg70MPbjrrz/lZnHWNu6ew1q6O7/Nug+wP\n" +
                "UdwFdbKnSAkX4rXjLyu4tvqH4akkwsn4QKSIpOQlaghbHLK+WL8ITUHzQv+m2Iv4\n" +
                "F02wWIIxaGYdD3bEIm3qMHRHoO4cfQz6GY2an4vjvik1a0sKM56es9XM8M+U6y3v\n" +
                "qKVudZb7p9xbGMjNwnPaBIpXwXS2XJaT2X3YZBpTBlhXrpAFc886TwvS5LqEzdLX\n" +
                "6WTi5NhJN0Y2yjoffRgrkQr5C+2Nd9pkcVHR+T5yQ9NTzJa3lgKfDY1ZJXTAQZjP\n" +
                "vXG5L02klQs1z5rrMPmQwXhZqgi2HelFaleZXrI=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0FJQVA1MB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowZjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExNjA0BgNVBAMTLUludmFsaWQgaW5oaWJpdEFueVBvbGljeSBFRSBDZXJ0\n" +
                "aWZpY2F0ZSBUZXN0NjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQU\n" +
                "JVlJJR67nbtRHW3D6vzK+HBOXh5S097ZMQEPce170libKgRiLesqEC9fNpzls8pN\n" +
                "VPwxOcZOgaHes1XlzdDkbf4TVXuprfJwcvHT6KWfzIehUopULihB/oJuMa289M0q\n" +
                "VFhS0XAhzLR8KPzNjyqEew5g20u4uvpDG2TQOO4QQgLJ8nQEtQuSTsAPK8E6d0sD\n" +
                "jgsHLOGETorVSgjW7zSIp2RZ1dNx8AEGm3l7tCl+xhkzKl7Me2W2qXJg+Iy17Jl5\n" +
                "0Ik0uj38yZaUt0LNuddEQaqZVGwh+19uZdbj8wD6QgHcF8sUBLeOHbKrsI8VaGvH\n" +
                "SHgiBW8dGWLp7rETQqkCAwEAAaNlMGMwHwYDVR0jBBgwFoAUiQRUdAZgs/cAbqBh\n" +
                "jhX7vlICBiYwHQYDVR0OBBYEFAOX8L+bVJZR0b0hAu1UhcFEzOxMMA4GA1UdDwEB\n" +
                "/wQEAwIE8DARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAFFd\n" +
                "fv8IwDnGrwxVdDqlMHz2fz7dZOnpMPRX5sleEzs0q11YJpVWu2VZJhDtqEFoLtZ8\n" +
                "7HRCdkeN3kI0RWsXhj/j5F1UdPKu3exA5aQ/+BQeeboF8DqbawC2kTf71cY48sS8\n" +
                "ECgGbXmd4dNI2ByZjMLVsq8ow9566ZpJZsfTEAw0dQ7TU9/4fasWSQ7LDFK/N9Z2\n" +
                "hqUS5eIJdveMB2HDL9o8pNohsA8smIfX0ARKCkcEbMTjLjEABcZKtK+y9cwdln3p\n" +
                "hQoA6GPCFY29vEqaq/T8XMNcWaTobelNsDMgKD9GZfa1CVnh1rwDve4f3PairHKm\n" +
                "h+iOTwouhOvswtsridM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCAIAP5Cert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Valid Self-Issued inhibitAnyPolicy Test7" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpzCCAo+gAwIBAgIBATANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowcDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExQDA+BgNVBAMTN1ZhbGlkIFNlbGYtSXNzdWVkIGluaGliaXRBbnlQb2xpY3kg\n" +
                "RUUgQ2VydGlmaWNhdGUgVGVzdDcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQDZ9LivETDywp+a/tfvaf8DhVHn9pKQKbNwVl8fS/Dnb9gyV5pPIalWgCr8\n" +
                "GoG0PFzmXvqA5eqdyEKzVNIJJyfF1ndYOaS+xs7DHBe4bszm56a+VXus9FdMOTSN\n" +
                "4h4L+D6C0hG6+ock4Y+TmXhPl+RKa2/S/NSLrXjk1pGOjLgoUVey7USRLSr0IP6R\n" +
                "+6E0Bto5TBPayBPUMRBUnhmmjg45nxAyHYxSsz/K9fhgpYFRfKeRafgV6Ndz83oZ\n" +
                "KJx/OywOV4e77PD1l9Cgzuc1s5OyWmb1tb440r+o9+FzF0eedHGD66qHmXpyCHJy\n" +
                "77ojQsHrMacGyDGXF8+QeEox1iqFAgMBAAGjazBpMB8GA1UdIwQYMBaAFIwF3N9+\n" +
                "ZNtivttLUWSMambYXKOjMB0GA1UdDgQWBBTZpaDF6bfRzvZDEtdOEJNc81hQATAO\n" +
                "BgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQAjl8+QP5Vo71I9RQDbigx5XlS6Anj0GJ/bVK/WQmZrfHs9JdHu\n" +
                "FKt7x5LL9AZQ/h7mVmSd8nM2z9KUpK3INlaKV7kJSOvskw3D48KNkD673fJfMkWK\n" +
                "rcznmtUVKMnkGqDKHBPfGSbXN2XEi2DsLY06Labo1mBEVigtLMxFGJ8OBIMuEtdK\n" +
                "MlhTISGom3Vs6WjeOcuFwz25vv0AWAJFdv31sFXDcxVvK/vvKkVyAlLJuh0fxw58\n" +
                "6avoUbtAFZW4gstzibCz+2aYvGoQSp4YatviYArYHYU0qQgYBXk4gF2UZCCJLrmz\n" +
                "WHhLJIfV/K5UFty8b1PuX2PONdktVBWymOhG\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1SelfIssuedCACAert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA2CAert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, selfIssuedCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid Self-Issued inhibitAnyPolicy Test8" {
        val inhibitAnyPolicy1subsubCA2CAert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDljCCAn6gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowVDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExJDAiBgNVBAMTG2luaGliaXRBbnlQb2xpY3kxIHN1YnN1YkNBMjCCASIwDQYJ\n" +
                "KoZIhvcNAQEBBQADggEPADCCAQoCggEBALAa5di9sE6N1APDJcqBi166iOEyhdim\n" +
                "UOR8WmLQQF+zANUCiwfgGLuTDU5DASaua8OodRLbdULKgYFqfOfFFaf1PXckA2OG\n" +
                "sCJx2W9LiMihDPFke5F36LTsoQ3FQ0D+ivyr6MhzyeaKnMIQ5+lZnzd5KLTYm8UM\n" +
                "FTMc3KeKwqj99doaZ2bkCF4YtdjacJwV88+7Qx2BHFYX/KKmM0V5ATMv2TAT7Hqh\n" +
                "2zA316mUcmMBXau3bYheXZMxvZsgUYic+FB1RUgWIu+lRUqFw5l0RnpbUvJR5dBq\n" +
                "78wtY39pQnROCm0q+/sOOWDGsaDxye4inrH6i5FX/kjJcgKDvX1GsHMCAwEAAaN2\n" +
                "MHQwHwYDVR0jBBgwFoAUjAXc335k22K+20tRZIxqZthco6MwHQYDVR0OBBYEFBF9\n" +
                "wJyKdvlJM/ekgUuOMHWVO+iIMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTAD\n" +
                "AQH/MBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEAs63PsCAJ\n" +
                "QfGsdCQ8SSViQpUxIIHmogbN4xTMfYk880Kjepk6FEXM2q3L89XKpi2oZiNxjfvN\n" +
                "YAZDSuLSVtfli9auc7RTtF+RXz5Pjs5U4htAHFz2JAf8nrAQ4sRBc7q8wwINGjRB\n" +
                "FSRHQUD275u4CYLsXf7dMy/m5Pe5FjQ8EdzuStshwoCTe2cSKv4r/YGqkBiatt4i\n" +
                "lsjfcs+sQDyZcQd2G9U2hGe+/uF4VXXOYq87ARie8osBUiVfDnRSdeTfTdLq8MB3\n" +
                "WYR7gQlA/OiTjvgyeKPYnM7RmKKCcYy3ZdXmsMnT9s1Zaqvw2Zh6xan4sWGbQRs0\n" +
                "mBDueMYtypQa3g==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDrDCCApSgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3Vic3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowcjELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExQjBABgNVBAMTOUludmFsaWQgU2VsZi1Jc3N1ZWQgaW5oaWJpdEFueVBv\n" +
                "bGljeSBFRSBDZXJ0aWZpY2F0ZSBUZXN0ODCCASIwDQYJKoZIhvcNAQEBBQADggEP\n" +
                "ADCCAQoCggEBANrGXh8C+n2LlFXpLZsOJgBIEL0cYBmcOraLKe7Uvg2hJc9AD8r/\n" +
                "z8WHmVQlSq4B8l5SFHNeRfZ80BEnvnpsTYyLF8ANVwtG5OT/tYqaJnda7njYnjML\n" +
                "hMkR8VHTaeplaXavFjQAesIG/JXDzHpX4U3FzcLo32jX30Jl0t1wSSVgufSYzPmz\n" +
                "vN4snvG+K/U6wIwW1Zj+bzDTf+WFNTL2KW+jEr7X8XfWi7gqNUaWdqkskRAkBM0n\n" +
                "CyiuRiEe9bFulCodYxEJB2pJKwdjXCxdHtJS3FiwOq86oOXgvThoQdHgxbAt7JWC\n" +
                "RqwyDXmi1cLLG5sioGKwAKDcE1jtuL9Ep2UCAwEAAaNrMGkwHwYDVR0jBBgwFoAU\n" +
                "EX3AnIp2+Ukz96SBS44wdZU76IgwHQYDVR0OBBYEFJ/nMvWSZoe1IShDy5EYfznX\n" +
                "2OM+MA4GA1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJ\n" +
                "KoZIhvcNAQELBQADggEBAJjr02r+qm4q+XG/oDosR+zfakP0pcDGVwwLwHqHV6i6\n" +
                "hf32iODdTy7N+3GfB1vOdWJ1HKJT8TbXcM/zyYyglvw9rXAWdeaTeZLExRaavB+k\n" +
                "LlIAycxXFl4gSslEqbxnGl7FN4BN8DAa+4WtHwW0Ff3U0wTbSNMBx4x7skvP/9ZO\n" +
                "8Qllw94V7dAwBUDwbVL185tJsJI87lMXUqxMdrBCGoa0lqS1I8ZFCYXV0TOCeeTI\n" +
                "ruSYrANu8eHRJliHGb4+SAZ9xVWFqsqAJyqrs+pJHFm4+7q/YdBeVjV70jTjN+R+\n" +
                "Jxh+nojv3Cn5l9DmG8xQZzc4Q3QTsd7Dpmb51+N+N7Y=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1SelfIssuedCACAert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA2CAert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subsubCA2CAert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, selfIssuedCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }

    "Valid Self-Issued inhibitAnyPolicy Test9" {
        val inhibitAnyPolicy1SelfIssuedsubCA2CAert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBAzANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowUTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExITAfBgNVBAMTGGluaGliaXRBbnlQb2xpY3kxIHN1YkNBMjCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAJJAVofrVfHs45uXKz4PgJkRHsgL1Z4e2sxf\n" +
                "Y2DoqXS9SaYI6WIGl8UaUaWu2GdEw8ogTo3JUrJI3fbDBRJs+aGFvBTaTjH9QuL8\n" +
                "EKXDHoMMTUpRy183wS6wbZKKHS42CxjBHR4zMmLhnCkFo7IEC2CsgxCTzUO9F8Dn\n" +
                "aWQ2LuoTTjD6O8POnTLawoqcioqQzvpGY/kYItrYGq43lSA4zaxToHFWrRSqmMhT\n" +
                "kjqGhAPpjemoUtPKhBfcMw5HSTP1ZWJUUZfXlH3OCuKzi7+dk//7JVzmPGSIP0RZ\n" +
                "KYY1bj3XjSS0/0VlbJBG8tOhAZT2DKvzMIPpvCMDJeEW45bBNYsCAwEAAaN2MHQw\n" +
                "HwYDVR0jBBgwFoAUjAXc335k22K+20tRZIxqZthco6MwHQYDVR0OBBYEFMnMP/pb\n" +
                "8KHa1TcMm86YxnqJK9XrMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/\n" +
                "MBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQsFAAOCAQEA1S7dJczr1Qzl\n" +
                "zL9tXuePIeWIEW+U0V7V3IAMJEy4eo1B7v5uHSdxCf+4syTypdB6rbNUmoK1cRp1\n" +
                "ChDyuQ4Yeiqj15HVD/anZ1Jo3zKnfr8KklVPEgiotUTSAV78aYJ1liCaZOBPK2n8\n" +
                "voSX0antIGJLILX/FxJWijpjOERnYpD+wQSWBcSifo2XYXplE/gD/HqyaVjGl1ec\n" +
                "Kh2j4bf4WS6P/QsW1h95SfOK9j7atKevgqWKY0lGePS89NoIyQHfhrXY25v4nwRM\n" +
                "iGB8d1zjzlpOVskFlrvlJu9TW+qQPsA3ZLiRBQZj1CEhU1n5x0e94K7LzEKL0759\n" +
                "xhV1ZzxcqA==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpzCCAo+gAwIBAgIBBDANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowcDELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExQDA+BgNVBAMTN1ZhbGlkIFNlbGYtSXNzdWVkIGluaGliaXRBbnlQb2xpY3kg\n" +
                "RUUgQ2VydGlmaWNhdGUgVGVzdDkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
                "AoIBAQDSWk+BxVIg223wvs2weR2LSJ3WElVnaJjergY5PUJWIpvi3rhr36NcMtCi\n" +
                "KTKwteK0gjEvuC1ViP8SDvC3F1jPx1mJUeCvLO+ykSWCHnoxo4jdtgUUFFazMkQo\n" +
                "Emf8o2s8xuGab+Me1byMnlNceqPD3q7ncenZumYeleV50CBz4zrz68rdT1/iRd3C\n" +
                "tSkQzXE15FBx6VVFimfY4b8Gsx/zrCOQtr7uuxwlKljVZIneyV3Oxtk8+9EuYXMk\n" +
                "Yig9pZSMVMU1nscG/qoPj35p/fduse+KRpGM2N3EebJjMC4WKI731mkenI5rRSOP\n" +
                "BIwiLPEi4lYgdX/DfqVBiYO2z3WXAgMBAAGjazBpMB8GA1UdIwQYMBaAFMnMP/pb\n" +
                "8KHa1TcMm86YxnqJK9XrMB0GA1UdDgQWBBTlOtW6qZkT1fSqlvvdOHn/0HslbTAO\n" +
                "BgNVHQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3\n" +
                "DQEBCwUAA4IBAQAw2XcoqDcFwz7cBnYxG7mEvhoTqnGLOrxF94XpTlAN49BUYfmN\n" +
                "iQF/mmWo/fA12Y5BwOBcAws7dDB0H428uhtqYBGCxuhzDkIXy3X4zvNO5P5XdrOw\n" +
                "oel1+zfi4hH3FEKLQmgEjJy2PN2s+JkqZNpxP670/tpp5wwB1DLN2bEc6AARlN5t\n" +
                "y/pvSd7sVBSXo6FaYO6USn4Fk/m2toWZrCjGZAZCJITWwjwLjQKo19FARC/iUNMQ\n" +
                "35sIs4EiP8bL/k5HcAZVXECK49Ogr6g9lU9wY9swx5Uudw8/2OstRe4vTQFw99Da\n" +
                "q6T+4P1VCKTMkXqfc7kR3vey8S1z88l6GO5M\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1SelfIssuedCACAert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA2CAert).getOrThrow()
        val selfIssuedSubCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1SelfIssuedsubCA2CAert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, selfIssuedSubCa, subCa, selfIssuedCa, ca)

        val result = chain.validate(defaultContext)
        result.validatorFailures.firstOrNull { it.validator is PolicyValidator } shouldBe null
        result.isValid shouldBe true
    }

    "Invalid Self-Issued inhibitAnyPolicy Test10" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkzCCAnugAwIBAgIBBTANBgkqhkiG9w0BAQsFADBRMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEhMB8GA1UEAxMYaW5oaWJp\n" +
                "dEFueVBvbGljeTEgc3ViQ0EyMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAw\n" +
                "MFowUTELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIw\n" +
                "MTExITAfBgNVBAMTGGluaGliaXRBbnlQb2xpY3kxIHN1YkNBMjCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBALF4YK3LWtJiBgUl5Tn3nfwLF69a8RzoolTy\n" +
                "yaH+AC5GnpkNUDC8Mae8jF0rRErvKDlDgHmHFYrEXoZ6ROCsqx2m0PCYcM0aSc5I\n" +
                "Nt0zfc0V/SjB8PEitoIsDTBNWQHoWBysMKdEvPcPgEbQ6g/I9AMuo2ENAu3JAK/k\n" +
                "mFT7y5P4Auk3pwAzK9eM/qiVVSoK62ykN2e90B/v/W8Mp2B1oSLkbrUq+pZdG0Cl\n" +
                "lqPw8jaA6/GRttWiOINW1MERdhyYXIZa9HrhE1vHQNBWT9ZNs0z8WXlSx0qSe5Bf\n" +
                "ZRC6U4A7HagfKnp97XwcfgzLEZVeRzq8ydhdKyYL/GIQ6skBA00CAwEAAaN2MHQw\n" +
                "HwYDVR0jBBgwFoAUjAXc335k22K+20tRZIxqZthco6MwHQYDVR0OBBYEFNeq4+x4\n" +
                "jtMItdkkxE+pjUaRGjiSMA8GA1UdEwEB/wQFMAMBAf8wEQYDVR0gBAowCDAGBgRV\n" +
                "HSAAMA4GA1UdDwEB/wQEAwIB9jANBgkqhkiG9w0BAQsFAAOCAQEAw+zWEOZ2oOy7\n" +
                "pak+z0Wn3q9yg06WNlv55x61qIF9FLPsUKHcq5HZNHUqYUXhsGP08cU5bIq20epK\n" +
                "xuAj34fGieLjH1KgbgG+Bwe8pkG43gzh7ggqdqcUEXQZFOMLlZz6AnRWeG8/ZoKt\n" +
                "J1u5XBLhBO6poXF8n3T8t0us4f+HtVOjdNeRdrS1QEiHrXLOanN6YIViBraciCOd\n" +
                "ezeYCJvDquy2ZCoAUDpJS6dofveoHGr4BpMDgLe1g19JWAbZhvHQ/WHzTJrMnd/q\n" +
                "rvpQcTRAwaLr/Sp3zY5tp4Mb7AV4iYYszVbwQQyHhsq0E590x6kQz6lVtKh7joOU\n" +
                "4naDVzv2ig==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(inhibitAnyPolicy1CACert).getOrThrow()
        val selfIssuedCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1SelfIssuedCACAert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(inhibitAnyPolicy1subCA2CAert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, selfIssuedCa, ca)

        val result = chain.validate(defaultContext)
        val validatorFailure = result.validatorFailures.firstOrNull {it.validator is PolicyValidator}
        validatorFailure shouldNotBe null
        validatorFailure!!.errorMessage shouldBe "Non-null policy tree required but policy tree is null"
    }
}