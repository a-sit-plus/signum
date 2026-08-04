package at.asitplus.signum.supreme.validate

import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.decodeFromPem
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TrustAnchor
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import org.bouncycastle.util.encoders.Hex

val PkitsSubjectNamePathBuilderTests by matrixSuite {

    val testSuite = json.decodeFromString<List<NistTestCase>>(resourceText("NIST-PKITS.json")).filter {
        it.name.contains("Name chaining:", ignoreCase = true)
    }

    /** NIST Name chaining tests */
    testSuite.asData(nameFn = { it.name }) test { testCase ->
        val trustAnchor = TrustAnchor.Certificate(
            Certificate.decodeFromPem(testCase.root)
        )
        val intermediates = testCase.intermediates.map {
            Certificate.decodeFromPem(it)
        }
        val leaf = Certificate.decodeFromPem(testCase.leaf)
        val context = CertificateValidationContext(trustAnchors = setOf(trustAnchor))
        val builder = SubjectNamePathBuilder(intermediatePool = intermediates)
        val chain = listOf(leaf)
        val candidates = with(builder) { chain.buildCandidates(context) }

        if (testCase.isSuccessful){
            candidates.size shouldBe 1
        } else {
            candidates.size shouldBe 0
        }
    }

    /** Source: https://github.com/bcgit/bc-java/blob/main/prov/src/test/jdk1.3/org/bouncycastle/jce/provider/test/CertPathBuilderTest.java */
    // fails because of the unsupported OID: 1.2.840.113549.1.1.4
//    "bc-java CertPathBuilderTest" {
//        val rootCertBin: ByteArray = Hex.decode(
//                "3082023c308201a5a003020102020101300d06092a864886f70d0101040500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465301e170d3032303132323133353230385a170d3032303332333133353230385a305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d61727920436572746966696361746530819d300d06092a864886f70d010101050003818b0030818702818100b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5020111a310300e300c0603551d13040530030101ff300d06092a864886f70d0101040500038181002584a067f9d3e9a02efcf33d9fb870176311ad7741551397a3717cfa71f8724907bdfe9846d25205c9241631df9c0dabd5a980ccdb69fdfcad3694fbe6939f7dffd730d67242400b6fcc9aa718e87f1d7ea58832e4f47d253c7843cc6f4c0a206fb141b959ff639b986cc3470bd576f176cf4d4f402b549ec14e90349b8fb8f5")
//        val interCertBin: ByteArray = Hex.decode(
//            "308202fe30820267a003020102020102300d06092a864886f70d0101040500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465301e170d3032303132323133353230395a170d3032303332333133353230395a3061310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531283026060355040b131f426f756e637920496e7465726d65646961746520436572746966696361746530819f300d06092a864886f70d010101050003818d00308189028181008de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fbde658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69020300ffffa381ca3081c7301d0603551d0e041604149408336f3240f78737dad120aaed2ea76ec9c91e3081840603551d23047d307b8014c0361907adc48897a85e726f6b09ebe5e6f1295ca160a45e305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465820101300c0603551d13040530030101ff301106096086480186f8420101040403020060300d06092a864886f70d010104050003818100a06b166b48c82ba1f81c8f142c14974050266f7b9d003e39e24e53d6f82ce43f4099937aa69b818a5193c5a842521cdb59a44b8837c2caddea70d8e013d6c9fd5e572010ee5cc6894c91783af13909eb53bd79d3c9bf6e268b0c13c41c6b16365287975683ece8a4dad9c8394faf707a00348ed01ac59287734411af4e878486")
//        val finalCertBin: ByteArray = Hex.decode(
//            "3082012430818e020101300d06092a864886f70d0101050500305c310b300906035504061302415531283026060355040a131f546865204c6567696f6e206f662074686520426f756e637920436173746c6531233021060355040b131a426f756e6379205072696d617279204365727469666963617465170d3032303132323133353230395a170d3032303332333133353230395a300d06092a864886f70d0101050500038181001255a218c620add68a7a8a561f331d2d510b42515c53f3701f2f49946ff2513a0c6e8e606e3488679f8354dc06a79a84c5233c9c9c9f746bbf4d19e49e730850b3bb7e672d59200d3da12512a91f7bc6f56036250789860ade5b0859a2a8fd24904b271624a544c8e894f293bb0f7018679e3499bf06548618ba473b7852a577")
//
//        val root = Certificate.decodeFromDer(rootCertBin)
//        val intermediate = Certificate.decodeFromDer(interCertBin)
//        val endEntity = Certificate.decodeFromDer(finalCertBin)
//
//        val intermediatePool = listOf(intermediate)
//        val builder = SubjectNamePathBuilder(intermediatePool = intermediatePool)
//
//        // target constraint is the EE's subject DN only — builder must locate the cert itself
//        val context = CertificateValidationContext(
//            trustAnchors = setOf(TrustAnchor.Certificate(root)),
//        )
//
//        val candidates = with(builder) { listOf(endEntity).buildCandidates(context) }
//        candidates.size shouldBe 1
//        candidates.first().chain.size shouldBe 2
//    }

    /** Source: OpenJDK test/jdk/java/security/cert/CertPathBuilder/akiExt/AKISerialNumber.java */
    "full-AKI EE Test1" {
        val root = Certificate.decodeFromPem(
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICfTCCAeagAwIBAgIBATANBgkqhkiG9w0BAQUFADB3MQ0wCwYDVQQDEwRSb290\n" +
                    "MRYwFAYDVQQLEw1UZXN0IE9yZyBVbml0MREwDwYDVQQKEwhUZXN0IE9yZzEWMBQG\n" +
                    "A1UEBxMNVGVzdCBMb2NhbGl0eTEWMBQGA1UECBMNTWFzc2FjaHVzZXR0czELMAkG\n" +
                    "A1UEBhMCVVMwHhcNMTQwMjAxMDUwMDAwWhcNMjQwMjAxMDUwMDAwWjB3MQ0wCwYD\n" +
                    "VQQDEwRSb290MRYwFAYDVQQLEw1UZXN0IE9yZyBVbml0MREwDwYDVQQKEwhUZXN0\n" +
                    "IE9yZzEWMBQGA1UEBxMNVGVzdCBMb2NhbGl0eTEWMBQGA1UECBMNTWFzc2FjaHVz\n" +
                    "ZXR0czELMAkGA1UEBhMCVVMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJvL\n" +
                    "cZu6Rzf9IrduEDjJxEFv5uBvUNMlIAph7NhfmFH9puPW3Ksci4a5yTCzxI9VeVf3\n" +
                    "oYZ/UrZdF+mNZmS23RUh71X5tjMO+xew196M1xNpCRLbjcZ6i4tNdZYkdRIe8ejN\n" +
                    "sbBoD7OAvPbQqTygeG4jYjK6ODofSrba3BndNoFxAgMBAAGjGTAXMBUGA1UdEwEB\n" +
                    "/wQLMAkBAf8CBH////8wDQYJKoZIhvcNAQEFBQADgYEATvCqn69pNHv0zLiZAXk7\n" +
                    "3AKwAoza0wa+1S2rVuZGfBWbV7CxmBHbgcDDbU7/I8pQVkCwOHNkVFnBgNpMuAvU\n" +
                    "aDyrHSNS/av5d1yk5WAuGX2B9mSwZdhnAvtz2fsV1q9NptdF54EkIiKtQQmTGnr9\n" +
                    "TID8CFEk/qje+AB272B1UJw=\n" +
                    "-----END CERTIFICATE-----")

        val intermediate = Certificate.decodeFromPem(
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIICqTCCAhKgAwIBAgIBAjANBgkqhkiG9w0BAQUFADB3MQ0wCwYDVQQDEwRSb290\n" +
                    "MRYwFAYDVQQLEw1UZXN0IE9yZyBVbml0MREwDwYDVQQKEwhUZXN0IE9yZzEWMBQG\n" +
                    "A1UEBxMNVGVzdCBMb2NhbGl0eTEWMBQGA1UECBMNTWFzc2FjaHVzZXR0czELMAkG\n" +
                    "A1UEBhMCVVMwHhcNMTQwMjAxMDUwMDAwWhcNMjQwMjAxMDUwMDAwWjCBhDEaMBgG\n" +
                    "A1UEAxMRSW50ZXJtZWRpYXRlIENBIDIxFjAUBgNVBAsTDVRlc3QgT3JnIFVuaXQx\n" +
                    "ETAPBgNVBAoTCFRlc3QgT3JnMRYwFAYDVQQHEw1UZXN0IExvY2FsaXR5MRYwFAYD\n" +
                    "VQQIEw1NYXNzYWNodXNldHRzMQswCQYDVQQGEwJVUzCBnzANBgkqhkiG9w0BAQEF\n" +
                    "AAOBjQAwgYkCgYEAwKTZekCqb9F9T54s2IXjkQbmLIjQamMpkUlZNrpjjNq9CpTT\n" +
                    "POkfxv2UPwzTz3Ij4XFL/kJFBLm8NUOsS5xPJ62pGoZBPw9R0iMTsTce+Fpukqnr\n" +
                    "I+8jTRaAvr0tR3pqrE6uHKg7dWYN2SsWesDia/LHhwEN38yyWtSuTTLo4hcCAwEA\n" +
                    "AaM3MDUwHwYDVR0jBBgwFoAU6gZP1pO8v7+i8gsFf1gWTf/j3PkwEgYDVR0TAQH/\n" +
                    "BAgwBgEB/wIBADANBgkqhkiG9w0BAQUFAAOBgQAQxeQruav4AqQM4gmEfrHr5hOq\n" +
                    "mB2CNJ1ZqVfpDZ8GHijncKTpjNoXzzQtV23Ge+39JHOVBNWtk+aghB3iu6xGq7Qn\n" +
                    "HlBhg9meqHFqd3igDDD/jhABL2/bEo/M9rv6saYWDFZ8nCIEE6iTLTpRRko4W2Xb\n" +
                    "DyzMzMsO1kPNrJaxRg==\n" +
                    "-----END CERTIFICATE-----"
        )
        val leaf = Certificate.decodeFromPem(
            "-----BEGIN CERTIFICATE-----\n" +
                    "MIIDLjCCApegAwIBAgIBAzANBgkqhkiG9w0BAQUFADCBhDEaMBgGA1UEAxMRSW50\n" +
                    "ZXJtZWRpYXRlIENBIDIxFjAUBgNVBAsTDVRlc3QgT3JnIFVuaXQxETAPBgNVBAoT\n" +
                    "CFRlc3QgT3JnMRYwFAYDVQQHEw1UZXN0IExvY2FsaXR5MRYwFAYDVQQIEw1NYXNz\n" +
                    "YWNodXNldHRzMQswCQYDVQQGEwJVUzAeFw0xNDAyMDEwNTAwMDBaFw0yNDAyMDEw\n" +
                    "NTAwMDBaMH0xEzARBgNVBAMTCkVuZCBFbnRpdHkxFjAUBgNVBAsTDVRlc3QgT3Jn\n" +
                    "IFVuaXQxETAPBgNVBAoTCFRlc3QgT3JnMRYwFAYDVQQHEw1UZXN0IExvY2FsaXR5\n" +
                    "MRYwFAYDVQQIEw1NYXNzYWNodXNldHRzMQswCQYDVQQGEwJVUzCBnzANBgkqhkiG\n" +
                    "9w0BAQEFAAOBjQAwgYkCgYEAqady46PdwlKHVP1iaP11CxVyL6cDlPjpwhHCcIUv\n" +
                    "nKHbzdamqmHebDcWVBNN/I0TLNCl3ga7n8KyygSN379fG7haU8SNjpy4IDAXM0/x\n" +
                    "mwTWNTbKfJEkSoiqx1WUy2JTzRUMhgYPguQNECPxBXAdQrthZ7wQosv6Ro2ySP9O\n" +
                    "YqsCAwEAAaOBtTCBsjCBoQYDVR0jBIGZMIGWgBQdeoKxTvlTgW2KgprD69vgHV4X\n" +
                    "kKF7pHkwdzENMAsGA1UEAxMEUm9vdDEWMBQGA1UECxMNVGVzdCBPcmcgVW5pdDER\n" +
                    "MA8GA1UEChMIVGVzdCBPcmcxFjAUBgNVBAcTDVRlc3QgTG9jYWxpdHkxFjAUBgNV\n" +
                    "BAgTDU1hc3NhY2h1c2V0dHMxCzAJBgNVBAYTAlVTggECMAwGA1UdEwEB/wQCMAAw\n" +
                    "DQYJKoZIhvcNAQEFBQADgYEAuG4mM1nLF7STQWwmceELZEl49ntapH/RVoekknmd\n" +
                    "aNzcL4XQf6BTl8KFUXuThHaukQnGIzFbSZV0hrpSQ5fTN2cSZgD4Fji+HuNURmmd\n" +
                    "+Kayl0piHyO1FSbrty0TFhlVNvzKXjmMp6Jdn42KyGOSCoROQcvUWN6xkV3Hvrei\n" +
                    "0ZE=\n" +
                    "-----END CERTIFICATE-----"
        )

        val chain = listOf(leaf)
        val intermediatePool = listOf(intermediate)
        val builder = SubjectNamePathBuilder(intermediatePool = intermediatePool)

        val context = CertificateValidationContext(
            trustAnchors = setOf(TrustAnchor.Certificate(root)),
        )

        val candidates = with(builder) { chain.buildCandidates(context) }
        candidates.size shouldBe 1
        candidates.first().chain shouldBe listOf(leaf, intermediate)
    }
}