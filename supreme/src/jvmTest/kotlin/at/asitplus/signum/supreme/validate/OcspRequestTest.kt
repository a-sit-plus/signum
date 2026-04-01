package at.asitplus.signum.supreme.validate

import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Time
import at.asitplus.signum.indispensable.pki.SingleResponse
import at.asitplus.signum.indispensable.pki.X509Certificate
import de.infix.testBalloon.framework.core.testSuite
import at.asitplus.testballoon.invoke
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import kotlin.time.Clock
import kotlin.time.Instant


@OptIn(ExperimentalPkiApi::class)
val OcspRequestTest by testSuite {

    "localOCSP" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDYjCCAkqgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwVTELMAkGA1UEBhMCVVMx\n" +
                "DjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5MREwDwYDVQQKDAhMb2NhbExh\n" +
                "YjEUMBIGA1UEAwwLTG9jYWxSb290Q0EwHhcNMjYwNDA4MDk0NDI1WhcNMjcwNDA4\n" +
                "MDk0NDI1WjBEMQswCQYDVQQGEwJVUzEOMAwGA1UECAwFU3RhdGUxETAPBgNVBAoM\n" +
                "CExvY2FsTGFiMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUA\n" +
                "A4IBDwAwggEKAoIBAQC2mefGY9mSPbWmDBj1NMwxJuJo8Tp65hSobBmutK3+LkTk\n" +
                "MOb6iIKZYojeGtnTHUIOshRpY9FbKKdTREgT7MMT8ktnCZxGQHQdCaUwu8rQI8yl\n" +
                "atpGNDVM5aEn9/6MwFdIkE0dQyO9AlpOC0Eon2dSGkYXy/sqR5l9wYiyREGzTZuc\n" +
                "Tgi5OayRMEFBaI6a7jskwIB0xgnR/s/vrcctrmyLVpoYViAkCVcBn8OQes5SBRzo\n" +
                "BC1fkq+UoBpQxSt4ED8JHnv104EgyBP+lA5RvLa1PlPwB27YDEvItopE23KDzBq9\n" +
                "EUMzrq3BFvPudjz+kJ2FVNeCdgnFTwK3G4+raYdhAgMBAAGjTTBLMAkGA1UdEwQC\n" +
                "MAAwHQYDVR0OBBYEFBav/L4WuI1jwlIzdvmTct5/uMy/MB8GA1UdIwQYMBaAFBFa\n" +
                "uMeoH63XFRzZGJ1fEOnI+zBfMA0GCSqGSIb3DQEBCwUAA4IBAQA0Emk2mXOBlYWh\n" +
                "4u87tq3J2VnZznL8FS472TbCR8Jsy57xjRi2alamAdk0DMBVo649KuDSFBfIHhBc\n" +
                "Vm+nOB0db2VKNrpivxJaztmXXPuaq/7S5B185U+Fem54OxWfEMKuh+U1Aeaiizuj\n" +
                "elCMBaxEmjD9BJlnM5jTHfVQdDsgP2kmv22g9FMPR+wwkWFt3ilLPzMHcOGza5Hz\n" +
                "P6rdrsY8XJ5ynGchKnp5CQPk92mMYejOPmw3pRRYy/AxYPh97G4DmEcUgvowYDUl\n" +
                "/XMK/K4xJx4ghJrz3I/8j3RL+CAeBinMDc6zwdFLETJXEEa3KPN9A4SUB8sGBqqB\n" +
                "KprTfGge\n" +
                "-----END CERTIFICATE-----"

        val caPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDizCCAnOgAwIBAgIUECURBbmQMDeexdDs1wAL+xISKPgwDQYJKoZIhvcNAQEL\n" +
                "BQAwVTELMAkGA1UEBhMCVVMxDjAMBgNVBAgMBVN0YXRlMQ0wCwYDVQQHDARDaXR5\n" +
                "MREwDwYDVQQKDAhMb2NhbExhYjEUMBIGA1UEAwwLTG9jYWxSb290Q0EwHhcNMjYw\n" +
                "NDA4MDk0NDIwWhcNMzYwNDA1MDk0NDIwWjBVMQswCQYDVQQGEwJVUzEOMAwGA1UE\n" +
                "CAwFU3RhdGUxDTALBgNVBAcMBENpdHkxETAPBgNVBAoMCExvY2FsTGFiMRQwEgYD\n" +
                "VQQDDAtMb2NhbFJvb3RDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
                "AMiQs0ZQO5HoMhNmIi36P7pTRRLf6wMmTYgyVczh7pYqsbJ0p4dHNpNXgrEtrjRw\n" +
                "Vn00kPJ4BYCHBiWh1DO6/6eoQRXCSMoeWSSPbKuj6EcYFlj2BfjmlWfnefW/kP5L\n" +
                "swSJICGjH0UUl+Fww+zAWmyka0G4W+eg3MNhUzvP2Qz0TB5pItqdiTIuQKbZqG/o\n" +
                "i9JMujQMEdhKwY/oDY0ft48SaCsAxuX/6knHEBoyoPNkuR28K9LHNExvAnkiOmB4\n" +
                "SKTC1nPmhR7+CdIQVDID9xxbxBy64PanGz/i7+wKto5ODAQVT3qxfNutfOTuduXH\n" +
                "27sPtjNz21I4vGUuy6tRxsECAwEAAaNTMFEwHQYDVR0OBBYEFBFauMeoH63XFRzZ\n" +
                "GJ1fEOnI+zBfMB8GA1UdIwQYMBaAFBFauMeoH63XFRzZGJ1fEOnI+zBfMA8GA1Ud\n" +
                "EwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAGAermGZXgIyQcx7LDBk4FoG\n" +
                "zVVGKSE2QNzkG3vLfLz42IkpBp6VUtvsX9Rim12tEvF3iLZ4c6xpNoje8lkJKsmF\n" +
                "GN/AOwWT+UX+7KFQMWGK8YG08D16vq/cC/n6fwWrwJabtpowFwwVSTd8vchBiH/E\n" +
                "FwiU5ElCyP2R5H9/ZRay5DVvvaLXXvC/mdbJC2bXwDUcjooZv/IZRVLV4p0ZbovT\n" +
                "ScPTB+IPWOJ8kR1sPVvesATSD5lf/2fTpC5uMkyfw/Kyq3JlkOJq2RdeIpFHrvGR\n" +
                "Y6s/EqBV7Ab+bWBnAJlavRcbiDONGV72QPgmD/c7IK3VPPT3UTzO1CrTosmwonA=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(caPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf), TrustAnchor.Certificate(ca))
        val ocspRevocationValidator = OCSPRevocationValidator()

        ocspRevocationValidator.validate(chain, CertificateValidationContext()) shouldBe emptyMap()

    }

    "CERT_PATH_OCSP_01" {

        val rootPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDIzCCAgugAwIBAgIBATANBgkqhkiG9w0BAQsFADAhMRIwEAYDVQQDDAlUZXN0\n" +
                "IFJvb3QxCzAJBgNVBAYTAkRFMB4XDTI2MDQwNjA4MTg1MVoXDTMxMDQwOTA4MTg1\n" +
                "MVowITESMBAGA1UEAwwJVGVzdCBSb290MQswCQYDVQQGEwJERTCCASIwDQYJKoZI\n" +
                "hvcNAQEBBQADggEPADCCAQoCggEBAKRKU0GF2CPEwXFFKBLQcYNuvJNrPuLyCVhZ\n" +
                "vf+Z1klUaBWJa3eEyAKkfANOq7KEB/6FZ8gF3UF+qDrwIm/VgoJRUKHzdGZSowpa\n" +
                "rw7vmxU6vu4VlggTWIBuWqymIhFjGyobhkp8hoB1xBrmHfGbh5Ns/WlQ1Sb1vrw7\n" +
                "Oen6gEBTY8b1Q7ixf73F3hdaxZ3ftBvJgoG61+UWNFWba1lT34alG5He6Xja4Snf\n" +
                "mBRtkG6jVCT5CvkowJUaGSNnVeY1iEhJ+u2cdZ7YLlt7z3h5wgs4qFATnn+IZE2G\n" +
                "u68Uh+sW1xMzHeSCIXuKNOEQfXR0pOZZW3E/Pro0njwIJZvEx6MCAwEAAaNmMGQw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFAOVXNkj\n" +
                "FxMBICIiiXOo/nW3R/hUMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEBMA0GCSqGSIb3DQEBCwUAA4IBAQCNVOwwYshkvPySZ5h8+AX0E6p6dxQVn8Kt\n" +
                "t5rBRjAiMEJELGGISIozRUdGuq4c5TU0DjrYm6eiP8v65hzmL7hFbgQNEm2al+rn\n" +
                "StzS0rMXt6TQdhmxoHULkku4DqDi9cxhAK/ShC9Ezy/R0sp9b4QNJ99JCPbZZPv3\n" +
                "q54ZUTjseywZmrTevpUMXLMqPfC2NamTg/7e9baidifGGEf36TTLfHiwa/74HdRY\n" +
                "C1YDT0l4NC9IuI+SBAjJd49IO7o9yMdr+28XqVGhmbnDH/ATrBss+RUlUJKfSfHF\n" +
                "UbUKm06fsVJrvxKerGjiPEASIOXjWsfemoPChRUWRZFdeYXQE5/b\n" +
                "-----END CERTIFICATE-----"

        val subCaPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDgzCCAmugAwIBAgIDAKR1MA0GCSqGSIb3DQEBCwUAMCExEjAQBgNVBAMMCVRl\n" +
                "c3QgUm9vdDELMAkGA1UEBhMCREUwHhcNMjYwNDA4MDgxOTE0WhcNMjkwNDA5MDgx\n" +
                "OTE0WjAjMRQwEgYDVQQDDAtUZXN0IFN1YiBDQTELMAkGA1UEBhMCREUwggEiMA0G\n" +
                "CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC21+h3HQgl+kCYX/fKgVbHmXXs/EWW\n" +
                "yGA1JRBreuU/yWApH7a9X2NCvcN9iqpqUqeEdA4TiA//nxH60lnMgDBs/b9Yakla\n" +
                "RBQ8kGXk6sA4j2aS/Un67K1NogRQl+GMXlVO6sAw4Q/NXxH+/gQ2k0QU7iJxcGI1\n" +
                "XmnEuReUOBJ32/a5ByzJM0DYwf5DNWwadButVx1xkujG+XGN4yBCPQ+QYGPYqHM5\n" +
                "7wgQ1pcNk8XvAxfXpaAnQ7FL4RbHwXnS4zr/p79mAuKV8LoML0dawmxQskLYN7OD\n" +
                "a5VyyfLdYiUtyNOXn9hGL+Jq0zgZ+ojoh9ZZ10hAySmy57LZaY6w7HDZAgMBAAGj\n" +
                "gcEwgb4wWAYIKwYBBQUHAQEETDBKMEgGCCsGAQUFBzABhjxodHRwOi8vY2VydHBh\n" +
                "dGhfdGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDFfUk9PVF9DQV9BSUEw\n" +
                "HwYDVR0jBBgwFoAUA5Vc2SMXEwEgIiKJc6j+dbdH+FQwHQYDVR0OBBYEFMuNk1ym\n" +
                "Q/+Kh1yzA/ICrYq5UYHnMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/\n" +
                "AgEAMA0GCSqGSIb3DQEBCwUAA4IBAQBqorAwfDKg5Pf0cOjvII1mG8QTfMjEhLf5\n" +
                "xBvGoftV8LtNRkpMGg25QkgZP5ADPwftYlNhDab/IeOYyxw3VwRfm17goSn1MmMO\n" +
                "QwoVzczsy7BfS6q/NRIdyhuQUoHfCMMT50IqxbtLHpAk6CkOJ2LVUj1Ug2I4k7zx\n" +
                "QPwwjsDvTLo8RUur4JTKQdnpu683ogA/T+FuKZd4iI1+V9wgRXSUtUvY2AjkoQf9\n" +
                "TKq+dWFIwXqR8nyCkUfmr0nPy2xaiuzP6sJuzJuUGy5PesoWAw5EZy+Ch4It/Zj4\n" +
                "WRomP9UPTbWkklosPZf2vBJeaj7eXwkM5bFcw0oOwuwvJ46vXjM3\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgICfWUwDQYJKoZIhvcNAQELBQAwIzEUMBIGA1UEAwwLVGVz\n" +
                "dCBTdWIgQ0ExCzAJBgNVBAYTAkRFMB4XDTI2MDQwOTAwMTkxNFoXDTI3MDQwOTA4\n" +
                "MTkxNFowHzEQMA4GA1UEAwwHVGVzdCBFRTELMAkGA1UEBhMCREUwggEiMA0GCSqG\n" +
                "SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC5QDHtGwEmPOcEf3MCcygsQHXXAmVQyDHy\n" +
                "y+HmVZEwCEnc+LxgnVblf4/vA3Wo5uz4e6BoOCG/DdRsdRypytzLGUV+35bDW0V5\n" +
                "NDMaqNmU+HFpmFVy8bYKs5AicxoGosM2PNSXHZbYwEnAn2oGgaanoH8YaQNlk0w4\n" +
                "70ECcNz38z94Ay99mMaOGCz6bslmjlhOkqbh6LFt25bi+y5/qgD2mgL8ACvSfkPp\n" +
                "VWB8MMdkfNX1TQiCxUz9x0dhgRuMFkU/OaCCZj4+pCcry8rxmCE1lw2BkucxLLbX\n" +
                "6mIysau5Imq9ceOSIQ5tuWgdjZXNd+bfis5AIqH6e60s2WNsnxYvAgMBAAGjgdww\n" +
                "gdkwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzABhjtodHRwOi8vY2VydHBhdGhf\n" +
                "dGVzdF9ob3N0OjgwOTUvQ0VSVF9QQVRIX09DU1BfMDFfU1VCX0NBX0FJQTAfBgNV\n" +
                "HSMEGDAWgBTLjZNcpkP/iodcswPyAq2KuVGB5zAdBgNVHQ4EFgQUoS28dLGQVqYB\n" +
                "vc8VwQse7PgtKb8wDgYDVR0PAQH/BAQDAgeAMA8GA1UdEwEB/wQFMAMBAQAwHQYD\n" +
                "VR0RBBYwFIISY2VydHBhdGhfdGVzdF9ob3N0MA0GCSqGSIb3DQEBCwUAA4IBAQBk\n" +
                "P0AzGityhPGvjLYSvXmYhTADEUKKMdBTbGzGCgpdhSI0Fnwe921mzLOnARwga4Qj\n" +
                "hz7QU8BsisoYwbLs3QXdxkX12X0B6yOhuF7YD0LbiWD/zu1kXK3Z4hkzTKczW1/j\n" +
                "uenIzyRa6xu1g9PwaG43T/mFhIM6S1eWHqSEzPFR5IyQrwdPyodZMXrkksplbm4C\n" +
                "a0td0yRaL6rUqT4OThz+QhSaQesaAgR3aXA1H+PDSZysxrBz23ZioXjd3xGWPcjD\n" +
                "WIdrsvE71Z3os3ku41DKUE0Xl9A9sfN16hgyie2SKgw2l555929Gq8PMYotUZHpA\n" +
                "hYBAE/Xc/BpubNgX98eB\n" +
                "-----END CERTIFICATE-----"


        val root = X509Certificate.decodeFromPem(rootPem).getOrThrow()
        val ca = X509Certificate.decodeFromPem(subCaPem).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()

        val chain = AnchoredCertificateChain(listOf(leaf, ca), TrustAnchor.Certificate(root))

        runBlocking {
            SystemOcspCache.initialize("./src/jvmTest/resources/ocsp")
        }

        val ocspRevocationValidator = OCSPRevocationValidator(
            DirectoryOcspProvider(SystemOcspCache.responses)
        )

        shouldNotThrowAny {
            ocspRevocationValidator.validate(
                chain,
                CertificateValidationContext(supportRevocationChecking = true)
            ) shouldBe emptyMap()
        }
    }

}