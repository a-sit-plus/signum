package at.asitplus.signum.supreme.validate

import at.asitplus.signum.CertificatePolicyException
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.pki.CertificateChain
import at.asitplus.signum.indispensable.pki.X509Certificate
import at.asitplus.signum.indispensable.pki.pkiExtensions.CertificatePoliciesExtension
import at.asitplus.signum.indispensable.pki.pkiExtensions.Qualifier
import io.kotest.assertions.throwables.shouldNotThrow
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/*
* PKITS 4.10 Policy Mappings
* */
open class PolicyMappingTest : FreeSpec ({

    val NISTTestPolicyOne = "2.16.840.1.101.3.2.1.48.1"
    val NISTTestPolicyTwo = "2.16.840.1.101.3.2.1.48.2"
    val NISTTestPolicyThree = "2.16.840.1.101.3.2.1.48.3"
    val NISTTestPolicySix = "2.16.840.1.101.3.2.1.48.6"

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
    val trustAnchor = TrustAnchor(trustAnchorRootCert)
    val defaultContext = CertificateValidationContext(trustAnchors = setOf(trustAnchor))

    val mapping1to2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDvDCCAqSgAwIBAgIBMDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowSDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExGDAWBgNVBAMT\n" +
            "D01hcHBpbmcgMXRvMiBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n" +
            "AOBrczl/53SePwB1Ub5qyWVoVLy1LCGwRkezm19LowdwFJkzJV0YgrlXpEd0TeBF\n" +
            "Wn3ObRNqZmcPBkvF9rUrRCmuMIuT+164rh+U80zAXVVJgPoCIWwAHKFyskha0L5q\n" +
            "3DjC+ZsIqZKajL/hQj4OmbKlvJuP0Ptd8Bjiy9bG7NgLohzt7BvI91rjKjFu98vC\n" +
            "nFvXrpFbPMyeatLKJ/x0kgHfPRQLCOot4ojSkQmbD5MZNNplW4G/4iWFCAwwsk5y\n" +
            "jA34AkwYIe6mcML4Te1wBGueM71iGaga0pPdLnzodPV5rr5+sjcKsW8yZ2C3jca1\n" +
            "ui0v1oDcQ5BR0dlvomx/VHMCAwEAAaOBszCBsDAfBgNVHSMEGDAWgBTkfV/RXJWG\n" +
            "CCwFrr51tmWn2V2oZjAdBgNVHQ4EFgQUmcV4acs9M3bCmaxE5bAO/rn028cwDgYD\n" +
            "VR0PAQH/BAQDAgEGMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwATAPBgNVHRMBAf8E\n" +
            "BTADAQH/MAwGA1UdJAQFMAOAAQAwJgYDVR0hAQH/BBwwGjAYBgpghkgBZQMCATAB\n" +
            "BgpghkgBZQMCATACMA0GCSqGSIb3DQEBCwUAA4IBAQCjpL09JCig5v+7S82FBPiu\n" +
            "JTT1xgO/XBQqRIvDkfggs3F4HZCJR+XuQiloEGY/H86/laXVMy/dTj5t/Ojq+8cB\n" +
            "+T6jWzmNLTvjQkuIrLkzIQ15bce0+1EYnKEVVw+0BGMfsAObXsJGLDxmE1DYRUZi\n" +
            "Bx+Ar5ZHwhTRXLNszYWSTXPR0oXfPly5YqFwnFWBAj4r0q6rUsIipcmIe1XuFMhY\n" +
            "SFNJJNWzpTMS5ay817vhfMb0koA+fdM91hmONDOo8wbT8CDr5hWhss1FEbAqFheI\n" +
            "RhYXLG7Mll5FWcfc7HbSU9+edq08W6aLsgXyupHF3SYrA0w0duk2l251GqwUgxx7\n" +
            "-----END CERTIFICATE-----"

    val p12Mapping1to3CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDzjCCAragAwIBAgIBMTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHDAaBgNVBAMT\n" +
            "E1AxMiBNYXBwaW5nIDF0bzMgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n" +
            "AoIBAQCybxVTY2ahevfz61NSr7Rud7Bmrim/64S25e221g2bswm3M+BTZ71urQ4s\n" +
            "JsDgpAew9ULwmJPjMBLbSqkkhld/X7p0q9ffmO10Vbgv5BzOHw71pnxP7qQlb6Tf\n" +
            "F1pDlYFDhxBYqpwxmvtgOuP5XgqlkYpCzcG0fziyhL/EmgOLR4FxaeiTejMvJEpo\n" +
            "XnN9El0THTG01qtbT6ZwLgz93yo3bxonxLRtQZtvkR6pjSJ6XF84IsUPY1CDoFdA\n" +
            "8v1Syir5cEHxYeSSkH5yJSf/KwZ+dt3NFPZDk1VAIyFqPk1UpgsG0P41UavWPetR\n" +
            "jrCB+1aydTyuHovXCrPof65cAbs9AgMBAAGjgcEwgb4wHwYDVR0jBBgwFoAU5H1f\n" +
            "0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFPz0jWEzMoB8fTWH3l9S+2nxHcES\n" +
            "MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MAwGA1UdJAQFMAOAAQAw\n" +
            "JQYDVR0gBB4wHDAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwJgYDVR0hAQH/\n" +
            "BBwwGjAYBgpghkgBZQMCATABBgpghkgBZQMCATADMA0GCSqGSIb3DQEBCwUAA4IB\n" +
            "AQCQi4Yo6SjeCW1k/l7Txpz5pQjamJUDfBmgcr6v8n6RfCN+1NoMXbXX1hgti03O\n" +
            "QsU+HAnZpB1B+2GNeNdtN7a8SSutKt0+ouswvZOK3w/3rC1AxJ/MIDMk5IvjBonu\n" +
            "TBnSQIIvLIWsXcub6aEEG61GpG7cK9GnMeY4NxUH3YIIPDJs9nrrcHEaO78s+6+/\n" +
            "rlt8+XuH4h2m+xv7xB+7GN8KKKSH3gZ03X1QpayGiw91rDX52O4EhfAQcxtNfX07\n" +
            "9VvpjEcfn5Lpbe6p8BfkziM+TVf8zZmbfwR3mwinTdcLBB8AxENAbN3Oau965reL\n" +
            "23HfMPn6+Rf8SYguskWt8K0W\n" +
            "-----END CERTIFICATE-----"

    val p12Mapping1to3subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID5DCCAsygAwIBAgIBATANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEcMBoGA1UEAxMTUDEyIE1h\n" +
            "cHBpbmcgMXRvMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaME8x\n" +
            "CzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMR8w\n" +
            "HQYDVQQDExZQMTIgTWFwcGluZyAxdG8zIHN1YkNBMIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAxEQSYM/pUi02SbG3+5QFT/rPnGdsz7WTlK84lI0muKNE\n" +
            "ZF3ZhSs25xj5+M6Kak1HkGxP0heWALuor0rEPzNX4W4zXbFfeZRzLtYef5vFix3J\n" +
            "5hVTVeKJncghN+/Ik2RDIubrcm8+rQKHW9f01ufxS0P7bc1cAueQSX+fQx4WaGiP\n" +
            "fwa3hI1PoWfDZGfZe6Yb/POwHIpwEI8gtmZ5++z42TxBeXktFk88+qmjDzFm3EL9\n" +
            "aARqFtOvCVnu4kZHNbHatq6mBsYV5WeJMENmihJj0bbOsmwxqmcgyrN+jTCkhyRa\n" +
            "lIywhZddOIyw5CqnB6ELwU4bEhgcQ3Srogm8sDJYAQIDAQABo4HNMIHKMB8GA1Ud\n" +
            "IwQYMBaAFPz0jWEzMoB8fTWH3l9S+2nxHcESMB0GA1UdDgQWBBS+exOToeSbxSc8\n" +
            "MFPXpcnmWpZ6NDAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAlBgNV\n" +
            "HSAEHjAcMAwGCmCGSAFlAwIBMAIwDAYKYIZIAWUDAgEwBTBABgNVHSEBAf8ENjA0\n" +
            "MBgGCmCGSAFlAwIBMAIGCmCGSAFlAwIBMAQwGAYKYIZIAWUDAgEwBQYKYIZIAWUD\n" +
            "AgEwBzANBgkqhkiG9w0BAQsFAAOCAQEAbH0Zzzdz7zKpAJHd0euOWLiP0Zs08+9+\n" +
            "d+JG/wsVrUwaJIFl5D/lBW6tMMqqkMERQNLoXW1PMf0joAeooxapJAcyc80G+CEv\n" +
            "Qjont75l9RswXOeOJDr6cjKgDfJ0Su488bJ22YAK4/ywiiZMXZ/kFbjFzN6VaUtS\n" +
            "jLHyB1L/tmahUMD1fWr1R06VFlwtaB4MEyBHRdYd0kr8pPEKTtIpvMYvgbHfpRqe\n" +
            "yCGfKTgRRCuAnP8T16Xajq9LPkJv2/QjHWpTgeRKA7ddWrmEH0VQcmpHYgoPMIkR\n" +
            "3uEv8/k8zdsI14AHOj5zUn9muQgFK4znUjvNspmqx4+x4S/3FjEoAQ==\n" +
            "-----END CERTIFICATE-----"

    val p12Mapping1to3subsubCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID0DCCArigAwIBAgIBATANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEfMB0GA1UEAxMWUDEyIE1h\n" +
            "cHBpbmcgMXRvMyBzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBa\n" +
            "MFIxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDEx\n" +
            "MSIwIAYDVQQDExlQMTIgTWFwcGluZyAxdG8zIHN1YnN1YkNBMIIBIjANBgkqhkiG\n" +
            "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtSGFUwgaiWWF5fUjELwFR+ISQbeAbroekuEg\n" +
            "LzcnZa41l5oBmVXW/YdwIa0lbI8TEYdbSJKMPmj/VBZi1qEWkZMG7AkeS6ZXV5IX\n" +
            "NZr3z5+xyUgLWNlWVvF5FMOi9oysAe8G3Lykzb7aEULDmSEJF08ZO2BAKmwqwHb5\n" +
            "YeM/Qpig2XRbR5sPebFXbCPHgtDC21KBFg1RB9mYvkvbyeqqKNivtfaPbDcs7l6L\n" +
            "Q5V4jxemwubG0n/b147PjTv5atcFsMozbY8AwRXhUZSv80Q3TpclTwbWoaCqc9Jz\n" +
            "dAlVN4YywNosJr1TuIOWuo5NFHvQZMrDE2UTd6wCsVX9e1hSKwIDAQABo4GzMIGw\n" +
            "MB8GA1UdIwQYMBaAFL57E5Oh5JvFJzwwU9elyeZalno0MB0GA1UdDgQWBBQAXTk+\n" +
            "D+WqKl4t9q5oKq0zmz2bczAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB\n" +
            "/zAlBgNVHSAEHjAcMAwGCmCGSAFlAwIBMAMwDAYKYIZIAWUDAgEwBDAmBgNVHSEB\n" +
            "Af8EHDAaMBgGCmCGSAFlAwIBMAQGCmCGSAFlAwIBMAgwDQYJKoZIhvcNAQELBQAD\n" +
            "ggEBACej7rCcrK7NKu8FFh2Rf3IUevcGIbr70Ussmb+ybpHCSgniO5b2qOHtRy4L\n" +
            "UGgSu4DW8oJpwQNiDfS4uFICS2Xfw1LImpY6WzsooMaBQOLUmpDfSNcW3vp930db\n" +
            "qWcqShq49BijeENbYGuJ5nJu6XctxdJq4CkfdLULItz057rcMPZ/v0r6WolizKb3\n" +
            "aOowWWR5iWPCfgKsK/pjA4CRZFdWkQeRcFZtpY9s7T3XWsYgzQ+RVSLKP8tuy+bX\n" +
            "+bXzpj2/FQ51kahd1XSilZ0YIhWrR7odQ1LIdlABuNmIcBAcTONhlpjrzx9Ukkem\n" +
            "CqvWf4hQHK7beuDqtx3JSiLMakk=\n" +
            "-----END CERTIFICATE-----"

    val p1Mapping1to234CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID9TCCAt2gAwIBAgIBMjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowTTELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExHTAbBgNVBAMT\n" +
            "FFAxIE1hcHBpbmcgMXRvMjM0IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n" +
            "CgKCAQEA6EPLe37qOTEdD6xUQELy7WcT/725FAHRtk/O46EgnyRbLY1VTw/549tQ\n" +
            "HEAeBnvBkfjD1c65JHMPFER6/LXHu1BT7EXfbaRPNvFFBrxO590dLZ7zkXggq+ZX\n" +
            "/RDwCs8HMEsOrGa8g61yaYFICkTlMCwC+gWKK9SPQj3TS+YFfkmPFkF22ASIttqG\n" +
            "+QPyy5BHx4WV1k21sjw0dijh9V1Z+tZ6cGLGVp490Bov1syfcz8FTmiscacXTOwd\n" +
            "hnlv/XFa+URTqDd7qvaiieYe3V7W7j1x0okIRENxZh1giKU0AcbAehfYgmXVT8Pg\n" +
            "/FG4oxhZ4fflmfgIa+k6tGf1KmDelQIDAQABo4HnMIHkMB8GA1UdIwQYMBaAFOR9\n" +
            "X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBSVCwGpSXiqdtp/CQ2siBT59fdH\n" +
            "kjAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1Ud\n" +
            "EwEB/wQFMAMBAf8wDAYDVR0kBAUwA4ABADBaBgNVHSEBAf8EUDBOMBgGCmCGSAFl\n" +
            "AwIBMAEGCmCGSAFlAwIBMAIwGAYKYIZIAWUDAgEwAQYKYIZIAWUDAgEwAzAYBgpg\n" +
            "hkgBZQMCATABBgpghkgBZQMCATAEMA0GCSqGSIb3DQEBCwUAA4IBAQBFCspJbnGl\n" +
            "9QA0VGqikE3JqvEe534hgJSjqUj3YXOdbHF3BzthYJxmCC8c8ZAQAj78LDctPO2E\n" +
            "doS23rw94Hx23MOOMy92xoCYepjNWffZMdSgxUMBeGCVSw+I7TPG82c34h/nRung\n" +
            "HcZ5OgG4p7j7DSiI6fbhdOxjvNPw1MTjYZd26QMcgqnsK4Ts0oCv2tiHsMWIX32I\n" +
            "ZZZqMruUNHrapJZoayDbBSbx0ecusf9xxky2I3of8j/EDDWujCSTS+2+ld89U1Hm\n" +
            "wLiGs4cGEHVkWT3bMpXC4vh6Ioh7MWcTGKGoH034mpOgMtG+Uixh8uWOmqvxlx22\n" +
            "GWtLzZ8NDh2L\n" +
            "-----END CERTIFICATE-----"

    val p1Mapping1to234subCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIID5jCCAs6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBNMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEdMBsGA1UEAxMUUDEgTWFw\n" +
            "cGluZyAxdG8yMzQgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAwWjBQ\n" +
            "MQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEg\n" +
            "MB4GA1UEAxMXUDEgTWFwcGluZyAxdG8yMzQgc3ViQ0EwggEiMA0GCSqGSIb3DQEB\n" +
            "AQUAA4IBDwAwggEKAoIBAQDCqo/fkI2CorkBLrk8+SW5B2Vf/V3rrujIfoLvDe7m\n" +
            "xMzVUsj3fQgZUgeD7yG056J8OLaaV2X6AnYGSOR/IjkmxnmChoDBNZHgfxmjoIBB\n" +
            "SrWaoYzucLOpPhxbRToBM68OV1YS7JuJyNZNOkpWCVDOnDUUGqZZJAOO9KKU2bW6\n" +
            "/mWamcohebtrQQsSUAJqatKBd3DFgyJl9toV8bWgINwNHPJOG/zGmfXrM0XpTC6c\n" +
            "cYqN3FnBO1BhuHvAmT7x9nKEP2d9+njVvSJijL5UefG2i3k73WD6FsK1NsD1TUiM\n" +
            "W8R1uObBWDJSp7tMnpsRzpWYxN2UrB9DfejvhYwCW60lAgMBAAGjgc0wgcowHwYD\n" +
            "VR0jBBgwFoAUlQsBqUl4qnbafwkNrIgU+fX3R5IwHQYDVR0OBBYEFAMX5ZUA/So5\n" +
            "eK/LRvZAmGUKAu27MA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MCUG\n" +
            "A1UdIAQeMBwwDAYKYIZIAWUDAgEwAjAMBgpghkgBZQMCATAEMEAGA1UdIQEB/wQ2\n" +
            "MDQwGAYKYIZIAWUDAgEwAgYKYIZIAWUDAgEwBTAYBgpghkgBZQMCATAEBgpghkgB\n" +
            "ZQMCATAGMA0GCSqGSIb3DQEBCwUAA4IBAQABbF8fZ+aayNEPK6IYowHdDmpCNyiX\n" +
            "ShlGuMbWbiSBilugkXB8z11tg/C+5D1wdeDk57vpcrmr63pjA/NVcJsp6nOFGsBT\n" +
            "A0l2TQ6GA6Yqk8ptm8nzP3tD60KfDzu1+Ld0eGCkx4BWjwGrOBt7S5K/G/tTAXQa\n" +
            "+fZ0nNP+WGn30vRze055JcSScogmNcTJ0sYLBjnYbxyFjpbyOsdhiudG+FufGcIH\n" +
            "P++VV//LWKA8t2DgMb4ejFdpihhWV8T8fLuvykmVJhD4QcV4Z+TTTW93QjCAa5oN\n" +
            "XWhzyqOe4s4GLlO7jZw1LMEHhh8M7Q3SIrEGDA/1exOutvigUAQ8x0eE\n" +
            "-----END CERTIFICATE-----"

    val goodCACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDfDCCAmSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowQDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExEDAOBgNVBAMT\n" +
            "B0dvb2QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCQWJpHYo37\n" +
            "Xfb7oJSPe+WvfTlzIG21WQ7MyMbGtK/m8mejCzR6c+f/pJhEH/OcDSMsXq8h5kXa\n" +
            "BGqWK+vSwD/Pzp5OYGptXmGPcthDtAwlrafkGOS4GqIJ8+k9XGKs+vQUXJKsOk47\n" +
            "RuzD6PZupq4s16xaLVqYbUC26UcY08GpnoLNHJZS/EmXw1ZZ3d4YZjNlpIpWFNHn\n" +
            "UGmdiGKXUPX/9H0fVjIAaQwjnGAbpgyCumWgzIwPpX+ElFOUr3z7BoVnFKhIXze+\n" +
            "VmQGSWxZxvWDUN90Ul0tLEpLgk3OVxUB4VUGuf15OJOpgo1xibINPmWt14Vda2N9\n" +
            "yrNKloJGZNqLAgMBAAGjfDB6MB8GA1UdIwQYMBaAFOR9X9FclYYILAWuvnW2ZafZ\n" +
            "XahmMB0GA1UdDgQWBBRYAYQkG7wrUpRKPaUQchRR9a86yTAOBgNVHQ8BAf8EBAMC\n" +
            "AQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8GA1UdEwEB/wQFMAMBAf8wDQYJ\n" +
            "KoZIhvcNAQELBQADggEBADWHlxbmdTXNwBL/llwhQqwnazK7CC2WsXBBqgNPWj7m\n" +
            "tvQ+aLG8/50Qc2Sun7o2VnwF9D18UUe8Gj3uPUYH+oSI1vDdyKcjmMbKRU4rk0eo\n" +
            "3UHNDXwqIVc9CQS9smyV+x1HCwL4TTrq+LXLKx/qVij0Yqk+UJfAtrg2jnYKXsCu\n" +
            "FMBQQnWCGrwa1g1TphRp/RmYHnMynYFmZrXtzFz+U9XEA7C+gPq4kqDI/iVfIT1s\n" +
            "6lBtdB50lrDVwl2oYfAvW/6sC2se2QleZidUmrziVNP4oEeXINokU6T6p//HM1FG\n" +
            "QYw2jOvpKcKtWCSAnegEbgsGYzATKjmPJPJ0npHFqzM=\n" +
            "-----END CERTIFICATE-----"

    val goodsubCAPanyPolicyMapping1to2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIDxDCCAqygAwIBAgIBFjANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEQMA4GA1UEAxMHR29vZCBD\n" +
            "QTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMFsxCzAJBgNVBAYTAlVT\n" +
            "MR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMSswKQYDVQQDEyJHb29k\n" +
            "IHN1YkNBIFBhbnlQb2xpY3kgTWFwcGluZyAxdG8yMIIBIjANBgkqhkiG9w0BAQEF\n" +
            "AAOCAQ8AMIIBCgKCAQEAyHIxLkjNU7QX3AYrkULGwUqy03uLcvbUEHQInt9Bp/Pg\n" +
            "XVX+CqX7DX4nF+BumfO3NZ1vgPO7fYrpw2igH+2wgB/eebl5xHhGzurjNNKJf1Rj\n" +
            "ikk0VDg7HVHpEoFZO+LQj+GVNj42mkrjEF9zhk8Gz1+K7I+MsdNN4qqJsavkO99s\n" +
            "ZKh8tuleFRUakUSdMDA8LrJbQgsfvVgrO2/AYiIwPiLbSRDqhNse3Hg4/+c9rQ5f\n" +
            "AxUBaW6j5gyNDbo3x9Zv4frFmtKqutRSzCHTfPXPsPduRozkQ9klYGOw2BDxiWfj\n" +
            "QTJYTESOFXwamS5hui8Y8J4Vunngk6WFtse3+VSTQQIDAQABo4GtMIGqMB8GA1Ud\n" +
            "IwQYMBaAFFgBhCQbvCtSlEo9pRByFFH1rzrJMB0GA1UdDgQWBBRbc3mZ464G04qm\n" +
            "M04UeOSgHbHkyTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNV\n" +
            "HSQEBTADgAEAMBEGA1UdIAQKMAgwBgYEVR0gADAmBgNVHSEBAf8EHDAaMBgGCmCG\n" +
            "SAFlAwIBMAEGCmCGSAFlAwIBMAIwDQYJKoZIhvcNAQELBQADggEBACIjsluMNLOx\n" +
            "owudQB61hn4d2AhLpSGzbgqU0PE7p/666w49TrJ66XGuIq0c+z/Xtl8mdGQ/lz2Q\n" +
            "CZqGNX0rb5NdjMV1MNJtEaiied89eI9sLBwbvu0cFAXeW6EYjyRCaQwh8/kn3K/b\n" +
            "Wvr1Tnj9SmBfyGaPoTZDpQ60rE2mrDL0CbKGnp4H/jIYtHnItuRe+ETOvkSiF0qG\n" +
            "X382kqIBHKji6xTF7HNHQr+C86OzdU0hffbCf38gt3LwUYn8MOKdInt1UEmKwG8W\n" +
            "1kqf3Y/IaGhhfBNEN8yNaJFNr+Bjj0blSkuqtt53jxHjXrZ9NPVmE6A7IAIx8av/\n" +
            "u7BUc8H7ALE=\n" +
            "-----END CERTIFICATE-----"

    val p1anyPolicyMapping1to2CACert = "-----BEGIN CERTIFICATE-----\n" +
            "MIIFLTCCBBWgAwIBAgIBNjANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
            "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
            "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowVDELMAkGA1UE\n" +
            "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExJDAiBgNVBAMT\n" +
            "G1AxYW55UG9saWN5IE1hcHBpbmcgMXRvMiBDQTCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
            "ggEPADCCAQoCggEBANzb/x7g9fYUZJHLawFd5dXdaTd5QI6b394FF+evA8+llsAl\n" +
            "r9BqwYe139iY9+RgTrroi8KRFeZaXndYBYANU+fvhLqFWAz3TK0nW+otpf5bJiCZ\n" +
            "27slpFJEINgrpLQpENt12YVkQ60alGIrvYIxjZkOrhbgwHqTxxMc98Nqdf9PXmaY\n" +
            "5qai+dWQ7RMewnkoX6bx1TmgQXOT17qlbOfyuAnYM1oabX1+86XEw7W69i6Cb8/z\n" +
            "/VkC6qeRbV1Pmu3lVRsoidYwGs2cwAyMOzz4MpTflSk3b56w0MbmHhyflr+/d5yp\n" +
            "mNAkE5dTqu0f4GZEACFbA0AP1qSbtgmG6vc1g5ECAwEAAaOCAhcwggITMB8GA1Ud\n" +
            "IwQYMBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBQfAigoMo5KhPi4\n" +
            "i0HxXXvoJVJrhjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNV\n" +
            "HSQEBTADgAEAMIIBeAYDVR0gBIIBbzCCAWswgbkGCmCGSAFlAwIBMAEwgaowgacG\n" +
            "CCsGAQUFBwICMIGaGoGXcTk6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9t\n" +
            "IHF1YWxpZmllciA5IGFzc29jaWF0ZWQgd2l0aCBOSVNULXRlc3QtcG9saWN5LTEu\n" +
            "ICBUaGlzIHVzZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgZm9yIFZhbGlk\n" +
            "IFBvbGljeSBNYXBwaW5nIFRlc3QxMzCBrAYEVR0gADCBozCBoAYIKwYBBQUHAgIw\n" +
            "gZMagZBxMTA6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9tIHF1YWxpZmll\n" +
            "ciAxMCBhc3NvY2lhdGVkIHdpdGggYW55UG9saWN5LiAgVGhpcyB1c2VyIG5vdGlj\n" +
            "ZSBzaG91bGQgYmUgZGlzcGxheWVkIGZvciBWYWxpZCBQb2xpY3kgTWFwcGluZyBU\n" +
            "ZXN0MTQwJgYDVR0hAQH/BBwwGjAYBgpghkgBZQMCATABBgpghkgBZQMCATACMA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBAQAJ4zsy9qL10OJy/VRk1NA5w+0ncD1kOXO0I2cHSqA6\n" +
            "wtQ6I23JPRgTutDfvR6ktvdBRfkeCwYHPVHHx9zrvfnk2MIAfdDeo93IVAqJEumo\n" +
            "LIoi+XEUWpRH1MiJbl74CndIpdc7G8H4OOagqMz1p2XsZ4K8RpF/H0WUYGvWsX7g\n" +
            "78EjEraD0D9PxWr1Na7kfnHoYxrqd/fmRYtnCwt26jO8A1DHXgrWerE/fnUlTxM5\n" +
            "tHHN1OMOlggOimhGvJ2pn05BdXIhVtmWCdFo6+pTcyWYMm2IvOrzEaQtnGf3Zefp\n" +
            "lObeComhN1QW5zDtLnzOhHUHc1t4deRAIN1zhE8vpYsG\n" +
            "-----END CERTIFICATE-----"

    "Valid Policy Mapping Test1" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkDCCAnigAwIBAgIBATANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEYMBYGA1UEAxMPTWFwcGlu\n" +
                "ZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowYjELMAkG\n" +
                "A1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExMjAwBgNV\n" +
                "BAMTKVZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmljYXRlIFRlc3QxMIIB\n" +
                "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1qw4n+hgG57EB2akKG9HJw0U\n" +
                "1wJcwQKfWv52eTaKNomMg19NaikNJj/iPcP1wdIjZAATRynTDN07kpReiNXkE6Re\n" +
                "5QdXFp8DzsOreH70CDBHDlPpvx10awKgAU24NiT2vEyGm3vee2V+gayPV4Afl+nt\n" +
                "Oh9kWODmCIJyDRG6l9j0R0fYLR3/DQT+w0AGb1He2RS2N1i6dO8hTEDImxqMPLE1\n" +
                "ezZmq+nq5MvWlTAlwbREnLXgB0i1GwZaL0RY1OogQbsxThAaGPqNJRW+qioH3A+U\n" +
                "qgWEheSueXoz2AZsnhDsw0hL72MvzG28BOFhqtdeRpOW3gddnnJ+peluBdgM/QID\n" +
                "AQABo2swaTAfBgNVHSMEGDAWgBSZxXhpyz0zdsKZrETlsA7+ufTbxzAdBgNVHQ4E\n" +
                "FgQUlaI8n8HPjmgNunyqQD8HV1jeilUwDgYDVR0PAQH/BAQDAgTwMBcGA1UdIAQQ\n" +
                "MA4wDAYKYIZIAWUDAgEwAjANBgkqhkiG9w0BAQsFAAOCAQEAq72hK/CqUQUKPp93\n" +
                "JCSZAQGtUruzmdRkery177NaQm/EDlhkXR0uEp2HToxIF0MJY20IMwBGR818tVEq\n" +
                "b/XfO8up2yg1T2gkKCAqU+JMEctVeTD1qzk1eDXKTi0pcfDJ6LPuTHNZ9AInFCmU\n" +
                "mczg+kqEGSk9Fwn/71Trzlm5oVkIsOv0CgTnoaSyp+qdSiBWYprSmwlwgrBnFMNW\n" +
                "tOA/ukHDQ7IdVq5iE8lfu0j2do9FV/a1W6uHuxb+ZiEWD9HJ1kJ8a/7c6g/e3Z96\n" +
                "/PuBVVJUnn8wD5Aun8yexdPAQC3ngJxEmb3a2lLlEI+FA4jRsaCBQHjKlQlZpM99\n" +
                "Dy3BwA==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(mapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo)))
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), policyMappingInhibited = true)
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Policy Mapping Test2" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDkjCCAnqgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBIMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEYMBYGA1UEAxMPTWFwcGlu\n" +
                "ZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowZDELMAkG\n" +
                "A1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExNDAyBgNV\n" +
                "BAMTK0ludmFsaWQgUG9saWN5IE1hcHBpbmcgRUUgQ2VydGlmaWNhdGUgVGVzdDIw\n" +
                "ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDP0ZnJwVL9VAfdOd5XKlTy\n" +
                "DBfVk0gJc5L/Xc1KAvdB4p8wMJnx08oy7X9zp2zJUdN8nMP8+C/PL9LssmwLIPCz\n" +
                "MfZJmiCynpann3CPnoXjlRyYZtHFMeW6D8ganSXetE4O1vKrCR0KOVU0xEwp5PuE\n" +
                "JvC2c9QrTyZQYKgv7Gj3zZ2QFNi46Mullsibu3FOWfVpncFDZMebzPS+qIfv5I5U\n" +
                "Vjec7wYjoSY25aL1/vDLwkzlTBkrPjGJeGb2oKeK1cmuDzHB5k6kPTpyBXYpF2z6\n" +
                "ifqjU/wLFo94hASA0l4cMh2IstJ+koKUZIuWOipTR5K2nDMywNpLyrHwdJ9Nwzwt\n" +
                "AgMBAAGjazBpMB8GA1UdIwQYMBaAFJnFeGnLPTN2wpmsROWwDv659NvHMB0GA1Ud\n" +
                "DgQWBBQc93qRn7CZN550xzB1rEvWIX+9tTAOBgNVHQ8BAf8EBAMCBPAwFwYDVR0g\n" +
                "BBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQDGxaCY0Qeaztw8\n" +
                "J0tdbO75i+EoXmPj8SdrzEvPS4YNnCsOt0sgBKQeP5BpfFScQgIoGHTt3leCUXlM\n" +
                "c6hu8rLTLB1Shs0ZSAPj+nmNx4LdppBbgZQ3KNBzhsgvz16CXK3PceMIuDfrcyRR\n" +
                "DtpqeIXCTp66esYzwq1LsdJuBdusYlkywZ/Q4NR8cHubhcAFM+iA289XjucldDDK\n" +
                "Xo1L2XERrSqXK3R4p1ZUIIcbYeFsOhZyBPU5UnXJcac4DG5LPZnnZxMAbUL8Rq+9\n" +
                "nx4NpZeML+uuIu+heoU51t2PzKDjJZOFhnspC7ZwrTmAYYIxTblTaZULF97Zvvc5\n" +
                "QKBZoV2y\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(mapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }

        val context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), policyMappingInhibited = true)
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Policy Mapping Test3" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZUDEyIE1h\n" +
                "cHBpbmcgMXRvMyBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMGIxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMTIwMAYDVQQDEylWYWxpZCBQb2xpY3kgTWFwcGluZyBFRSBDZXJ0aWZpY2F0\n" +
                "ZSBUZXN0MzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANBofqJQybQy\n" +
                "hloY6wTFGeWWDQq79xScjYNcGS3cgblO19DDYa+gw/1/6p2iVy7NxRnZRUCGSLXi\n" +
                "f5dXWOaCE1oiyUWBbd0ToHI1MAlsDmXv4LsGceJzr659aeSRNn3aq2uQ4HgezAfn\n" +
                "vPKL+OqnFTyaXD8VcPwoptkSoCVjG3qO/6O8X5xSI3UJZl+Pr0KeaQZpLJVznUcc\n" +
                "dGROiHNUYzt/NgkxqPxusg1yfLlv1zKTl8ggf1j5uXbp305FLVAKWFENS0InNiZl\n" +
                "gbSenXwg110BwtBQjE1cSRmD5xPqrmrCDuNBz1M11vB3TCFTlJLYBcjT/kn56e+P\n" +
                "P0fixAdywAECAwEAAaNrMGkwHwYDVR0jBBgwFoAUAF05Pg/lqipeLfauaCqtM5s9\n" +
                "m3MwHQYDVR0OBBYEFFdyv16sxo14G5DAn5RGpP4eU7xaMA4GA1UdDwEB/wQEAwIE\n" +
                "8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAgwDQYJKoZIhvcNAQELBQADggEBAE0+\n" +
                "Wkm1qVJobS6Lj4Au2vE32CuEL8H3Oi3jvfREIRH8wyFkYrEIDNnV1yKqMaYtvnxx\n" +
                "62U1tMJKwXDHYENtgregZDVl9xtFYvNj3VXXBfeWyR/hZA9bsqf5KBmTopPCrADx\n" +
                "BgZuGWnUhfcFFvUYVCgyCtrwCZXDgdoOab0oFq9gR6RyUJ/MbjSSsBzqILe7sPGy\n" +
                "7bbKX7zeBN71c0lwfyUqXdqw2Ar/yyqtqY5xR0Y63hBhENwc0FOqlQRqzRdxieX0\n" +
                "OdrRgGDiWUdPueXm6dE1ID6raiFgkbNjDS8P9w6JITApVYU2lf+FykcXUPJVbXeG\n" +
                "4fQjsbxrjEFK9aUJduM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p12Mapping1to3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(p12Mapping1to3subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(p12Mapping1to3subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo)))
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Policy Mapping Test4" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnDCCAoSgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZUDEyIE1h\n" +
                "cHBpbmcgMXRvMyBzdWJzdWJDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMGQxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMTQwMgYDVQQDEytJbnZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmlj\n" +
                "YXRlIFRlc3Q0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuOegev0I\n" +
                "rw/xlikpHk/FMYCcY96SImlDS0RBDaTJkie8ehC41c2dn4GAWeTxoFn5c+joQ6dq\n" +
                "Y1Po7teA59bYP4USHordfUKh7UjD36NPQnzbfU4GVUmVksb0f5PdABQnRwmYH+AX\n" +
                "ZaCfS37WRuoge7+XqUza3YLgY32y1Fh9VPNRygcGfvbhyYv4S2T+qruvc70C5ILB\n" +
                "lBGt+deKtqDqngE+7DZEZN6hn3H8Fgme8AAPdx48JNTLi4apId9Aag0BR7MMb0nC\n" +
                "Ntz463ci+/EhcD3HYZihuoZQ+kDlF2/zQOukhnebBpUv3VZqDuCvGJUAZPRrDRRo\n" +
                "dK5QZ6BSyfJ1zwIDAQABo2swaTAfBgNVHSMEGDAWgBQAXTk+D+WqKl4t9q5oKq0z\n" +
                "mz2bczAdBgNVHQ4EFgQU8p5RygFbuse22sy2ekGu4lIT1zQwDgYDVR0PAQH/BAQD\n" +
                "AgTwMBcGA1UdIAQQMA4wDAYKYIZIAWUDAgEwAzANBgkqhkiG9w0BAQsFAAOCAQEA\n" +
                "bXWDCbc7hJbeoWLcbO9gVwLftrtj68acV7Z+Jq0giW79OirTxTOZz9qmrkHiVZ+M\n" +
                "l5EdyY8TYchJBzxztll0mpbCc8j4tdin6H7I5X6/+RnTp3OBN6yln9X9Ap1iJTzA\n" +
                "t8y0K0LR55ytAMboQBvv7Qzd5AaWV3LP5Ue1QbrSMBwy5CBeUz6wKktrgzXUn/UM\n" +
                "Nmuf01iaEAt/GbhrSxC4EaUIF3P3H1u/TI/8Jw3uKdKnCMl1I/FGxeJyQL5CqJ9a\n" +
                "jFoZCpRcYKFItuPzr3HIpcjqaiZTB/qJXCLOQr4Vc2HAIOtt/eV2FXIc3pgqi87p\n" +
                "wojndjN58Fvx90EZIkOiMg==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p12Mapping1to3CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(p12Mapping1to3subCACert).getOrThrow()
        val subSubCa = X509Certificate.decodeFromPem(p12Mapping1to3subsubCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subSubCa, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Policy Mapping Test5" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXUDEgTWFw\n" +
                "cGluZyAxdG8yMzQgc3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBiMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEyMDAGA1UEAxMpVmFsaWQgUG9saWN5IE1hcHBpbmcgRUUgQ2VydGlmaWNhdGUg\n" +
                "VGVzdDUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmiGMLjXA2ijC5\n" +
                "itMpJVXTbHXhguDwZQ2mcSY5FmZ2nPuO2JBp2lA6yUG7fCuxTKeC1mGSOej41Pz8\n" +
                "zTkOGiXC/UtDy73yQhJJPHFn/ka7HzC3UlIOzRbY3nXg89sqIrO4wFLKUvrM1VkW\n" +
                "FqXJw5XbDwrL/0vIhqHh7jyK64snUiP0AAm6kgR1r3aufS1/QwjozIkRGmP4Cxm/\n" +
                "8Gzz5is4kfB2NuaR8xE/i8BubAM8TnAyIXX6hy99TlyyXSD2tc8dlxTskD8lt6IY\n" +
                "w0NwwNTi9Rqq41ZKkLtixase00o+s345noAcI5SfLdnTKXM6zUwooJzBW/av+8C7\n" +
                "YyqmOjS1AgMBAAGjazBpMB8GA1UdIwQYMBaAFAMX5ZUA/So5eK/LRvZAmGUKAu27\n" +
                "MB0GA1UdDgQWBBRLgjD1Mqn9+vaGwm3k1zO/qu1RFTAOBgNVHQ8BAf8EBAMCBPAw\n" +
                "FwYDVR0gBBAwDjAMBgpghkgBZQMCATAGMA0GCSqGSIb3DQEBCwUAA4IBAQBSG/qP\n" +
                "hRrenfviZJK/kxNaJzIM2ppVq3YbCxbjSApzL/tqPFEKtJuw2r7UlAY05rqzaZyE\n" +
                "1sxWuvyenub6f/K9BCQRBXHO5cPOnWS142x9komCqDUP7I7F4pnptXAp8nyc8eoL\n" +
                "zmsOJ8dlZv2aD//mISoFMZ69fvfIku/MAOZCTnSks1CPyT9omAfT6zdnMiDfk/kY\n" +
                "lZAWFas9/pm16Z88QP8y0z/IMrri12dOLMnFyKNBy/9TXNZof/VPkkD2keJ6eQGn\n" +
                "MUamXI/OIlBJXqu3AYiUDP9FQbxKxj4uTOtS1MhrZbAtTAI+3eqPKU92T8YFamCr\n" +
                "A1Z483lYO5ntY6/Z\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1Mapping1to234CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(p1Mapping1to234subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicySix)))
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Policy Mapping Test6" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmDCCAoCgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXUDEgTWFw\n" +
                "cGluZyAxdG8yMzQgc3ViQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBiMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTEyMDAGA1UEAxMpVmFsaWQgUG9saWN5IE1hcHBpbmcgRUUgQ2VydGlmaWNhdGUg\n" +
                "VGVzdDYwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvhuKxV6OvBRjA\n" +
                "hr758hKWi26IfFd2aGOgdDGd0/1i4wrW//nS3R8mVimchkGruRx1lB0KyEBYmAE0\n" +
                "hmep3SPwapk2xbej0UL9WgLubmfHv5iesAqn+/gFGyNrHx9/uzp+Ua+25BUGYxBC\n" +
                "bcMIIN06qMTU1dZF/nqNCPTO4uzdgH9VVnQHkI/TWLmrT8rrq44slyOebfCeXZeV\n" +
                "G2LtDcubaYdJlo4NJPPE15zrXPBxL4m0pFWPHeTUcEyDwJulUjFmX/NIjUF7yyvn\n" +
                "LlpLDHFFSzA4bVLOh0rI2VSy2ac1izMJx0gDnil7CykRofgkxJ9nmjclJ8pHtDVc\n" +
                "TKRmps+dAgMBAAGjazBpMB8GA1UdIwQYMBaAFAMX5ZUA/So5eK/LRvZAmGUKAu27\n" +
                "MB0GA1UdDgQWBBSzX9tBAp4J21F61Yw77Wz/CmsSAjAOBgNVHQ8BAf8EBAMCBPAw\n" +
                "FwYDVR0gBBAwDjAMBgpghkgBZQMCATAFMA0GCSqGSIb3DQEBCwUAA4IBAQBpUnko\n" +
                "RHAEZlhGumDpYCRzwa47JJqYthnJicarIhlRPpk6p+JkxZh1ISOfOtvfi9ApLNgf\n" +
                "O+Vr2M1Pd7nWfczbWcmKaa2QqcMU7c/r+KZ/1u4kN12BMlW8TY1o0kk7bBsqjpNt\n" +
                "6qAdQ+drFBIk7CxmaJuruJxSWZq6+EKy6MzeZiXUPOeujDaxqO3qixQK1iphIZMJ\n" +
                "MpF8Ls+p9Y/KZ3M4HrUteKvYCY37QzApC32yZmuOojxJOm1+kEV3rzb79dA5epJL\n" +
                "2nm2oLv8/C8gg7c1v4SpXUoR/d6hgLqu1jZCDFPMAN1Fv2eiWwU5sV2DcSY4bs7j\n" +
                "yxy3p3hdJLiP6KQv\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1Mapping1to234CACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(p1Mapping1to234subCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        shouldNotThrow<Throwable> { chain.validate(context) }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicySix)))
        shouldThrow<CertificatePolicyException> { chain.validate(context) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Invalid Mapping From anyPolicy Test7" {
        val mappingFromanyPolicyCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDvTCCAqWgAwIBAgIBMzANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUjELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIjAgBgNVBAMT\n" +
                "GU1hcHBpbmcgRnJvbSBhbnlQb2xpY3kgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IB\n" +
                "DwAwggEKAoIBAQCrp6IDBPUKqlzfwBrwMM0/8mXKVyogMBl5xjRYIAzPCs0Mwv7R\n" +
                "kEQbM1BIsYtbSJgsFJtldgS1u2yhYklqgcTsHZK7NrBL/QleugZcze2gunSlvAYW\n" +
                "2qO6t9japmswZ5/8l2hTia0T7P7Nk9lcBbDi+HjNDRqZglalb/gXvfWnsWxOxAiS\n" +
                "QY35dAnqxXl5KlkscU7uvsQubTBmNaQHsDrxoqSAXnMZG8dys1G3ET5Emp6FvYBZ\n" +
                "LSYQqK2nWkL8xFIbbdureHpD1Af+HWFDTntlZzw1Vb2MXvmz0pYFdRGA75KD7SSp\n" +
                "LEl5BiXwPLMF/UHmMZWhqVug0MlJ7mWl1UkzAgMBAAGjgaowgacwHwYDVR0jBBgw\n" +
                "FoAU5H1f0VyVhggsBa6+dbZlp9ldqGYwHQYDVR0OBBYEFGhzFOALNM9yQNqUltYV\n" +
                "q3qkby6MMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MBEGA1UdIAQK\n" +
                "MAgwBgYEVR0gADAgBgNVHSEBAf8EFjAUMBIGBFUdIAAGCmCGSAFlAwIBMAEwDwYD\n" +
                "VR0kAQH/BAUwA4ABADANBgkqhkiG9w0BAQsFAAOCAQEACkuUlU5OLnBP9XTQLJdC\n" +
                "4cZ2L1LbaCvAnUSD5ZU1UyDAPHcs+YsbjerZT1Alt/KqnVyD9pvkUuScevjjvLCy\n" +
                "fSGq4slrV8mHUVBbMuumv5q+0Z4J2PFgNXIvdxHiIRFUq9A189ZiQkfUxSeRPUK4\n" +
                "M3YmPO0iaeuS0SlAKIQ8a1dxNgm9ax8GOj+SQsx84FxED2wCR024sOajIHIPVvyh\n" +
                "bWPQMQbdJVSuVULjsfuGDyMZyN6a0gR5uBQ1MXmsIVrnwAia0LTH7kjudgabGYa9\n" +
                "MJkUVscZiu01jZBYfDqpaCN4MWkXCNvf9gksys7HoBvFlGyHm32/XiFrVKYufBkf\n" +
                "iA==\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBATANBgkqhkiG9w0BAQsFADBSMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEiMCAGA1UEAxMZTWFwcGlu\n" +
                "ZyBGcm9tIGFueVBvbGljeSBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMw\n" +
                "MDBaMGwxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAy\n" +
                "MDExMTwwOgYDVQQDEzNJbnZhbGlkIE1hcHBpbmcgRnJvbSBhbnlQb2xpY3kgRUUg\n" +
                "Q2VydGlmaWNhdGUgVGVzdDcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQDF9e5qo1oWtVVI+OfFQW0ZD4HihKuXcOZyHrCSc/UQJuc4inG5/g8CLClzXX9g\n" +
                "xSnOeyREom5k1AY0N+W/ynyH31lbKPVZvBmT/nMMhgzIVq691d3O3wSIiYEH44Oi\n" +
                "wMyhkY+mCRHerh0LktpIX5fnmS0FvT1wYAVFiECrFPCOR2cNsvKL8KZOutoJYtIG\n" +
                "nM2QtKcUYfdYhwpKq+3f1ae8nlErlhWS8GIn0C7E8x1HPeoCPAoPBuM9BDsa4q7R\n" +
                "tQ8vkCiL+7mMMf02mBvY6qddPK+LpCvaFZSTFGFZwX7T+TQUXnZtYRFjI0aMWajm\n" +
                "X7NGQYjwDrojn0v07UMmjLmlAgMBAAGjazBpMB8GA1UdIwQYMBaAFGhzFOALNM9y\n" +
                "QNqUltYVq3qkby6MMB0GA1UdDgQWBBQxi4iTbnfO7LvkRyyrlaUs+tKzdTAOBgNV\n" +
                "HQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQA730R9YAV/PansUKZky4hN5m2RQibLIju1MNH6xqQD0T7Bkq4aP1mQ\n" +
                "TqzZbk7n7v1hcLpLxDZDQnZZ1AQAHQl5JNjLMwKgonL8gX0YLIypXXFeZtxU7oJR\n" +
                "zdmVNPxTmcnPgLcMm6uPVRGR76qV2DhhgSWYV4C4ewIuEG1Zl6x4azJ5eOkL5xp1\n" +
                "yM9ara/0T+lGywgOr06T0+76/Kmwrr+kF+fHXkb5r8unU32lvSpIuKKxkyjEcN6A\n" +
                "1s9g6BxFkfpNVzZUuXphYoAy0olkMAvUWmrAeMz/jP9Zq4Bmq8UHLGmFFg4y5+fh\n" +
                "6OV3RFRDk3BzX8WuG40rlzE1IYgDDmV/\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(mappingFromanyPolicyCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<IllegalArgumentException> { chain.validate(defaultContext) }.apply {
            message shouldBe "issuerDomainPolicy must not be ANY_POLICY"
        }
    }

    "Invalid Mapping To anyPolicy Test8" {
        val mappingToanyPolicyCACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDwTCCAqmgAwIBAgIBNDANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUDELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIDAeBgNVBAMT\n" +
                "F01hcHBpbmcgVG8gYW55UG9saWN5IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
                "MIIBCgKCAQEA7l+P4Iahif8g4OYCYpPVwbmJqrG0fnDR/oNBlVnC10F/uJiYK6a1\n" +
                "7tCVcPXTHeD3N1XtvviZzr4hPny+F8DoVAyYsBQPn5pQ9YchgrsnMfuTmp6NGGt+\n" +
                "4kTW2K97AwgH+cRwm4/5xZgsKZS4dUVSySds2Vl1tLxK7DH1nrjSvieDO1k6h6Pi\n" +
                "fHZ/nfVI0CrPP+jwrPdUllp9lNv6IyrwO4gAEWUzVhwuqnEErKDA7FDLCMS/MG5I\n" +
                "3rWJ+1UMN32/IZlRj7b97Obe5vmXUtcnVOPTtmKPF7Crctq9EnAxOz7aZObY6qAY\n" +
                "6OJvaNCLA1YhHxNvSACVm6UdXaMeyodR3QIDAQABo4GwMIGtMB8GA1UdIwQYMBaA\n" +
                "FOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBQULO2T8R4acBWUiy2TtJjS\n" +
                "twUIrDAOBgNVHQ8BAf8EBAMCAQYwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA8G\n" +
                "A1UdEwEB/wQFMAMBAf8wIAYDVR0hAQH/BBYwFDASBgpghkgBZQMCATABBgRVHSAA\n" +
                "MA8GA1UdJAEB/wQFMAOAAQAwDQYJKoZIhvcNAQELBQADggEBADHu2GnJgEBdzRt+\n" +
                "PSfkyzvActmVetZktEWh3fysA8LTQI0lPBN4us1QKw61o9KtO+ssVs83d3OF5l3X\n" +
                "vkO4ilHyvT6Hz8bH5pXskMmXqYubrJI3lQjn58GohHNyCUDS8bYRDLe1Twz/t8VG\n" +
                "hLyiQwNQknc/8h6q/oQuilB794AHTDP84np7rsT24X93LOTxQoEdZXhB0gvBK8FE\n" +
                "j37F12ObeB/3fKRCW0kYo4leBgcPw5G7jm6z6nljCgvn62LBosINe6f4Gy++CLHc\n" +
                "TVW3OsNOIrgSBqrZr0JfAwykOWfqJGCfOQGcOIP+MyFkGHL6jrS8WnLoM/b4I5a6\n" +
                "NOBfmzU=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmjCCAoKgAwIBAgIBATANBgkqhkiG9w0BAQsFADBQMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEgMB4GA1UEAxMXTWFwcGlu\n" +
                "ZyBUbyBhbnlQb2xpY3kgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgzMDAw\n" +
                "WjBqMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAx\n" +
                "MTE6MDgGA1UEAxMxSW52YWxpZCBNYXBwaW5nIFRvIGFueVBvbGljeSBFRSBDZXJ0\n" +
                "aWZpY2F0ZSBUZXN0ODCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMr1\n" +
                "1erPw8vN57992tE1rFW83nzG1kHn6XMLHEmZkIdJASQbO/ZReTiFot1Xi+K6PpBO\n" +
                "mGbcSQ8uXLxWZVCk4fIwD6a0MU2Jmy5oHWFd4dqDmsBUroCbhiU5wrDWv49zV6ap\n" +
                "PmqPeQrLsN7FV0cwrFqS6YqU7MHaBkEoRlFvT8FyvyDb2SYaMbF1Vc3GPWudBQPo\n" +
                "Uq8qwpBYriAflA3P2dO4bTnr09XDZxV2FGbH6cVuKVpwErEHFYZ77ykngP9VfTQO\n" +
                "dXhygSD0jWvCgTqg5jXkcdfyyT1zxbVSGusMw+lBh3wBJKo0hJWq0Qup7GQkFV09\n" +
                "m0iTMj1vhbasHvBCPDUCAwEAAaNlMGMwHwYDVR0jBBgwFoAUFCztk/EeGnAVlIst\n" +
                "k7SY0rcFCKwwHQYDVR0OBBYEFKLkfME6MVHySnJusYPgXpJL2uCoMA4GA1UdDwEB\n" +
                "/wQEAwIE8DARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQELBQADggEBAE2j\n" +
                "J+NBiXf7fiA+1jBa1NWMTi/Fkrt7h35JicUUr6GGsfmS722UHOxcnqsxm22aqu04\n" +
                "HYld9m4FA6/ntPRQj1uDw26FM3r9sPXKExdF+Ohufqd7ACiiE4KXF94Be5oHk6YP\n" +
                "tfbMxoNx1C6gJqAr5nqLLGxuV/NfUKH2RnvU2QDVNZ1MjlooubzTtEeORrVnLqIh\n" +
                "8Qt3olTa1dYY1t+bAmea7+vyVd7aK+CXQ/iSCyVpX+oMkJGh263OLXGsniXK1A3d\n" +
                "HWf5jgBRLr5aUQe4prFZ/cgM+gFe0QNe88ObgrgKHL14OJw210WKHazf1xQKErar\n" +
                "Jk9IJeH/nwZq46/Nhn0=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(mappingToanyPolicyCACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldThrow<IllegalArgumentException> { chain.validate(defaultContext) }.apply {
            message shouldBe "subjectDomainPolicy must not be ANY_POLICY"
        }
    }

    "Valid Policy Mapping Test9" {
        val panyPolicyMapping1to2CACert = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDwTCCAqmgAwIBAgIBNTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEVMBMGA1UEAxMMVHJ1c3Qg\n" +
                "QW5jaG9yMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4MzAwMFowUzELMAkGA1UE\n" +
                "BhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVzIDIwMTExIzAhBgNVBAMT\n" +
                "GlBhbnlQb2xpY3kgTWFwcGluZyAxdG8yIENBMIIBIjANBgkqhkiG9w0BAQEFAAOC\n" +
                "AQ8AMIIBCgKCAQEA7it5KgqlOm7kgx373idsdbNuWSP2si6O6lKKZSjz/B/ER+zK\n" +
                "sbo30/ZnpGepghDagsI2z1pvXZPjFcaX5jThOtKnKiB00ColGZQL9OMl52BYfHV8\n" +
                "ygtI6FLosSe6J8A5grqnNiFUqupOAMS1MjsLDJssMivMyz1Mmb0FBqXzJOB3pMCS\n" +
                "nvgsLsM+rXXZYTJ69SJZfv4W31iGyRQer57qoIiKYTypLuBqO2S0baY7J//g040q\n" +
                "Sav7szmAh+K+Alseyheko9BY6tDW4kFSe2DshTvovJD6dZukmjh1IVLoU8LBMYy3\n" +
                "/23tKavxkEyXBYbrF5MjJdyfHDulSIw24P5kzQIDAQABo4GtMIGqMB8GA1UdIwQY\n" +
                "MBaAFOR9X9FclYYILAWuvnW2ZafZXahmMB0GA1UdDgQWBBRHAycvQz3FL9mSrMfS\n" +
                "dtAzxvl3uzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAMBgNVHSQE\n" +
                "BTADgAEAMBEGA1UdIAQKMAgwBgYEVR0gADAmBgNVHSEBAf8EHDAaMBgGCmCGSAFl\n" +
                "AwIBMAEGCmCGSAFlAwIBMAIwDQYJKoZIhvcNAQELBQADggEBAEzmc6/HFDjAm/BX\n" +
                "XujVfL34xHXsQ6Hvo5BiQHACompgIWEya5NwZQODcH4pig04UBkUg14d9VayDUic\n" +
                "gAnwUdsAvL3tHqwnTafckHMmsYJSig0xkxpOyWbqcq/RVHGnMy3pLXGTrX2jpI/0\n" +
                "1fYdE8EB5pcoL8MmktyTf51FvGJGQhQk0pIaCHhO5cHUADHIBdowWt8G31z4Kv/P\n" +
                "GqaZygDC2R1YG5btN8EJ4CSGp2bGX0oMJOt2F7knvVVrIFNGH4vYfuXSxuQ7yuma\n" +
                "kfS42S44/ES8W+FnhTW97iIq13l7Wh4XTvgfhHiT44dxbX9uUHH7TJqJq/rijbF/\n" +
                "0zDEus4=\n" +
                "-----END CERTIFICATE-----"

        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDmzCCAoOgAwIBAgIBATANBgkqhkiG9w0BAQsFADBTMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEjMCEGA1UEAxMaUGFueVBv\n" +
                "bGljeSBNYXBwaW5nIDF0bzIgQ0EwHhcNMTAwMTAxMDgzMDAwWhcNMzAxMjMxMDgz\n" +
                "MDAwWjBiMQswCQYDVQQGEwJVUzEfMB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMg\n" +
                "MjAxMTEyMDAGA1UEAxMpVmFsaWQgUG9saWN5IE1hcHBpbmcgRUUgQ2VydGlmaWNh\n" +
                "dGUgVGVzdDkwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC+P2NyLxKH\n" +
                "FxAPjW+SjKAbIRefIhK1wrsTiAqxwAXyFdd7DGr1yZgRDI01vPYyYCRCx+N4L1S9\n" +
                "rDC+mmh+zyDlsM9cQOaApF6Q8yoLW203kJIb2RWaxIL3kWhpQZsVVZ/feMaFM/3/\n" +
                "TlpjJlCTXyG5rBEz9jorFf4gaLzqfqROlojVWNN7ozp0aSe0hb6PrTymHOxA76u8\n" +
                "ahz41lNzczNv3UgfzijurhYx93GxKvM+uzSkcz6in1HaNVI9EYb/DgeqhnOW+eNX\n" +
                "lRBVxIt8Bib7ATofuBQCnPRzvC7txybCPX1KN32Ey3enhlRnFNXeGcEdEcevSVLw\n" +
                "CZ6KkeB+ft+BAgMBAAGjazBpMB8GA1UdIwQYMBaAFEcDJy9DPcUv2ZKsx9J20DPG\n" +
                "+Xe7MB0GA1UdDgQWBBQIZAJOoXdyajkMnsi9d3w/HMoLfDAOBgNVHQ8BAf8EBAMC\n" +
                "BPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATABMA0GCSqGSIb3DQEBCwUAA4IBAQBM\n" +
                "SaSdAKgMib7Hlpoooy+Du7GZe9IkYyp9XEhiugaOHtQzdD07PS4kUUjjtj/+RjAd\n" +
                "JB72SZBy6TX0MZoWhz6E4Zn9XwGmxWPAs2RwIcV7ICLq9ZvnThoCk1rUNRJN2GUJ\n" +
                "rKAaHnnJ8eplpFy7pe+XuSX3+BmuEsB8cY+UJML3DR3pfSP45I8hM4YP6a5C3HTd\n" +
                "Lif+xigdnT5hBD7UIDXTMxfBFFufc4Ckr5ON3bRRgQKzkV3+FL57dWqBweZV8wIm\n" +
                "WfW/8BXJVho3Tm7hj2m5Kl7GxuaicnVC9zjC02xSX2zWatlAC9qQ8PebqWHdNCt8\n" +
                "a+IKJC+4NrcghSNUs/eR\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(panyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Invalid Policy Mapping Test10" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpjCCAo6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMiR29vZCBz\n" +
                "dWJDQSBQYW55UG9saWN5IE1hcHBpbmcgMXRvMjAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGUxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTUwMwYDVQQDEyxJbnZhbGlkIFBvbGljeSBNYXBwaW5nIEVF\n" +
                "IENlcnRpZmljYXRlIFRlc3QxMDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n" +
                "ggEBAKgYrs2bp2rDpT6ZXc4PgBYjMV+WHjSqGUgrAPdR62UDChqzNHrE1Pw0Lgh2\n" +
                "IoWY+M7poGGp2Gsl9puYwBnXoViJ4dcD3EHwJGG0FvlWGpvKbV3l1AAd7cEJHokv\n" +
                "S72hma5YVH20kPfdF3Kd34WZNZTY14L0k+h/COfBuL9EQfq47rmSAiWLy1K+4fBF\n" +
                "jgc2Fo+UG37bpSxjZqTVt0dPmHzaJT5Ft9WfElx9GDQPl8tMES5gbY2asmubPk6q\n" +
                "FmG6ey1hM5Tn4EvoouxgHEEAKqeo6jZVPbVgDgL6vKiMbmDUUvB+ujR+diuvmp2L\n" +
                "HxrVx1s2bXkD9mkal41OxPy9/c0CAwEAAaNrMGkwHwYDVR0jBBgwFoAUW3N5meOu\n" +
                "BtOKpjNOFHjkoB2x5MkwHQYDVR0OBBYEFPG//ujd6Iehzjh3gjYhBFAefR0kMA4G\n" +
                "A1UdDwEB/wQEAwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcN\n" +
                "AQELBQADggEBAK96lyXiY85zaUn/7YefYb8m7f0S+IghFiiq8tbityudKhvMlna6\n" +
                "0C/os+x2O5Mhy84okB3MBcjghp9/Nl2WUnyYyO+BjCeDk51xyAFNtXl5VkEsa029\n" +
                "vfMKMWWOy51egYnVzErYmeud4H5pOFB7+x/55hMbMRrs6ww2eqtuM+i14iYKLNaM\n" +
                "MIAMJKMjGUu20CoNnEeYz/lLCtcD3+/qlMrBcnM+H662A46e6L+5Q/o7mMyQQCvc\n" +
                "jMKI90clD+5t7o6pA/rhv0wSpYz/GAcGciuAA5GMuJJOZjHSycMISz3nrBFvo6Jr\n" +
                "F5tYb+cl5W0BUCJDswlj4X0wWsXvblfOG20=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(goodsubCAPanyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        shouldThrow<CertificatePolicyException> { chain.validate(defaultContext) }.apply {
            message shouldBe "Non-null policy tree required but policy tree is null"
        }
    }

    "Valid Policy Mapping Test11" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDpDCCAoygAwIBAgIBAjANBgkqhkiG9w0BAQsFADBbMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTErMCkGA1UEAxMiR29vZCBz\n" +
                "dWJDQSBQYW55UG9saWN5IE1hcHBpbmcgMXRvMjAeFw0xMDAxMDEwODMwMDBaFw0z\n" +
                "MDEyMzEwODMwMDBaMGMxCzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRp\n" +
                "ZmljYXRlcyAyMDExMTMwMQYDVQQDEypWYWxpZCBQb2xpY3kgTWFwcGluZyBFRSBD\n" +
                "ZXJ0aWZpY2F0ZSBUZXN0MTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB\n" +
                "AQC+1d+dhBTDr0hkQGmjN35m1EjSSp6klcio007bUt1XEDFrmlcLqUaXwh7h2Llm\n" +
                "uQls+Tg+dLpiJNkS+rFqhiMY/8juZ0cJ8kTzzD3tF2Nn6Cjt9643MAFgpJhS2m01\n" +
                "/6jf4BSbLIy4bZCpes+3X63YPn7HkypNh/praDdnsBl6FVdMVFgSVF/IugL4OQHd\n" +
                "sDGFTlxLbslcKPdGGKnMWRV1M7Socp1saxeNISc7O0PxN3HZcxthxcmQIw6yYCRQ\n" +
                "sGM2nbm3kqvjVDKP4A0wxirsP44bIuO+XplnSIjflFDDYmwHdwHRQj3wY9bBBmp4\n" +
                "cjCNkcCanyNupu7ervRfxQT3AgMBAAGjazBpMB8GA1UdIwQYMBaAFFtzeZnjrgbT\n" +
                "iqYzThR45KAdseTJMB0GA1UdDgQWBBQ3/goQT3nXcdLj9bsgs0wszyJ9qjAOBgNV\n" +
                "HQ8BAf8EBAMCBPAwFwYDVR0gBBAwDjAMBgpghkgBZQMCATACMA0GCSqGSIb3DQEB\n" +
                "CwUAA4IBAQCqSXXia8C9CKK76G4gSKmXrWLRVJ/uE6oXYEKiGRWKny3sKj1sadSF\n" +
                "M4k2OfXuYCYUUvs+kZAulOeUZ02oh6WOEY9o4YH508JI5jyFeCzObQYqL4G84NyQ\n" +
                "Cz96Tedck64RUvcuPw6BqyrpMqVQslCrJGY/O+2jZ5kWi3pRd72r+z/6e7OvS/N8\n" +
                "F5VRU797A3vTwbbM1tjBlz0nVyezE9rdo81xP68jeKRnveQXsn1RGUSMLnT6vJbT\n" +
                "KGU80YD/l6dJgBS5qhgGYYk4ZxJuHBkoBfeHuM0NcwZHfqYowccNub7q8x1fiNoj\n" +
                "lo2TLCGcjka1s6RCQnucPVgfxwq1D8lC\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(goodCACert).getOrThrow()
        val subCa = X509Certificate.decodeFromPem(goodsubCAPanyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, subCa, ca)

        shouldNotThrow<Throwable> { chain.validate(defaultContext) }
    }

    "Valid Policy Mapping Test12" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIFNzCCBB+gAwIBAgIBAjANBgkqhkiG9w0BAQsFADBMMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEcMBoGA1UEAxMTUDEyIE1h\n" +
                "cHBpbmcgMXRvMyBDQTAeFw0xMDAxMDEwODMwMDBaFw0zMDEyMzEwODMwMDBaMGMx\n" +
                "CzAJBgNVBAYTAlVTMR8wHQYDVQQKExZUZXN0IENlcnRpZmljYXRlcyAyMDExMTMw\n" +
                "MQYDVQQDEypWYWxpZCBQb2xpY3kgTWFwcGluZyBFRSBDZXJ0aWZpY2F0ZSBUZXN0\n" +
                "MTIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCsR+um2sZ2YQ1PJDMx\n" +
                "PRcsr0/O2t34DJXXvPuOJwddAxPoy89/ARwwYTkA9PXt9KgKpui/y4zFKMEbA+8H\n" +
                "bZLQDzwxIxLtL8sxEarXLfvaCnmRDlw/gW0onAhdfcfxfrmlX2c2IaPulEzU14xE\n" +
                "DgnBF+c2XgmRDRZcBTVrrdcHf7/pvnYU+De32CTzBJLox3TAALRveoFaHEBI79/9\n" +
                "BELaRR+ar6oiKByFa3WMM8vszIr60pC1S22V6kq9Mz1EEpZo6RyfqzzbInXQYG0f\n" +
                "6PS0sz5lDPHxBkNJh1LmIubJ5T4/Wz+eDaHkUYVtj4o8b5Jvab2kbOiy89E5slOf\n" +
                "xsGxAgMBAAGjggILMIICBzAfBgNVHSMEGDAWgBT89I1hMzKAfH01h95fUvtp8R3B\n" +
                "EjAdBgNVHQ4EFgQUH9UDtvGnSGlr19U5qGCO40QW4Q8wDgYDVR0PAQH/BAQDAgTw\n" +
                "MIIBswYDVR0gBIIBqjCCAaYwgdgGCmCGSAFlAwIBMAMwgckwgcYGCCsGAQUFBwIC\n" +
                "MIG5GoG2cTc6ICBUaGlzIGlzIHRoZSB1c2VyIG5vdGljZSBmcm9tIHF1YWxpZmll\n" +
                "ciA3IGFzc29jaWF0ZWQgd2l0aCBOSVNULXRlc3QtcG9saWN5LTMuICBUaGlzIHVz\n" +
                "ZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgd2hlbiAgTklTVC10ZXN0LXBv\n" +
                "bGljeS0xIGlzIGluIHRoZSB1c2VyLWNvbnN0cmFpbmVkLXBvbGljeS1zZXQwgcgG\n" +
                "BFUdIAAwgb8wgbwGCCsGAQUFBwICMIGvGoGscTg6ICBUaGlzIGlzIHRoZSB1c2Vy\n" +
                "IG5vdGljZSBmcm9tIHF1YWxpZmllciA4IGFzc29jaWF0ZWQgd2l0aCBhbnlQb2xp\n" +
                "Y3kuICBUaGlzIHVzZXIgbm90aWNlIHNob3VsZCBiZSBkaXNwbGF5ZWQgd2hlbiBO\n" +
                "SVNULXRlc3QtcG9saWN5LTIgaXMgaW4gdGhlIHVzZXItY29uc3RyYWluZWQtcG9s\n" +
                "aWN5LXNldDANBgkqhkiG9w0BAQsFAAOCAQEAfgUmAvc8LV3+9l0DE8PptL9L43/o\n" +
                "bdmYSWhMK8uW7yPnOAyuntZKIT/ssu9oSHFL9dBP5HAnJWslHJqimNZAGanekms0\n" +
                "uXkiqBOIEP6aMcnRKd734CgiZwnpcFzjPcVFySmBmu9/MtPOGXd4t6n8RrOewe9m\n" +
                "0HEi0c5/FzdmXz4KtIrTxRSeB1MGtle5kz9ks4Jv7YVyqg62vagxSxYIYIQahYTG\n" +
                "e3ilDUmdh9ws0RmJgp7PTQ/gV5qUwfWfv/tMWhNUyA/9bdCql87yhNTxokTdkmiZ\n" +
                "N4ZkwYg0No52Fiue+ymxwvF5R6P36fDEP0phyjh6qv6NYxsdXwd97AfS9g==\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p12Mapping1to3CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        var context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyOne)))
        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(context)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyThree } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }

        context = CertificateValidationContext(trustAnchors = setOf(trustAnchor), initialPolicies = setOf(ObjectIdentifier(NISTTestPolicyTwo)))
        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(context)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = leaf.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
    }

    "Valid Policy Mapping Test13" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnTCCAoWgAwIBAgIBATANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUDFhbnlQ\n" +
                "b2xpY3kgTWFwcGluZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowYzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExMzAxBgNVBAMTKlZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmlj\n" +
                "YXRlIFRlc3QxMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALnps/1m\n" +
                "3VaOuWJUszOp+AmWnTRIwJe3yRXQ/ysvNkLsbmpqhnmrpxIMjmcttViCxNj6BQ8y\n" +
                "AjVAtnVSADQBiPP0ETES+3NEW8/VghqYzGJJ9H1Oxanks1Ef8mI58uQm9EWkqTJ/\n" +
                "B+UjxgqCKkHhmkikpVT/SupdPALhgRw4cta4oouQ51jqoW4rDJrRhMdlPJ5Vaiu9\n" +
                "m1N9vPK3FIKHMQGV3t1x8u/8T4xsed6ZynU+05zTwnzNl9mu3mX60lfRkLeSUeMa\n" +
                "p31xBaivLBPyEB04dzzGQaXdhBN5PaJfw98+xLjtK18L26+jqSf2BPfUVDitbCQx\n" +
                "HyLvSWWN6qntVaUCAwEAAaNrMGkwHwYDVR0jBBgwFoAUHwIoKDKOSoT4uItB8V17\n" +
                "6CVSa4YwHQYDVR0OBBYEFDxAEkPP6QrslaJxGaIDcd2mbH1QMA4GA1UdDwEB/wQE\n" +
                "AwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAIwDQYJKoZIhvcNAQELBQADggEB\n" +
                "AErtqbfufFlEyw6M9vWlfiVDCONgimPxftB15iPZe0zL/kVsUk6URd1rcQItVKBa\n" +
                "ORFqxKp+VRg3kYdzgMUeRJB242zed+QryQlZIoaLmp9JGN/rz4P1gBzIYNmTy/pw\n" +
                "kKqzkUQbzIWlf/0A1wCpI9LAxgT1TRJ5gLF8r1DrAUzB8GwH/vTzNkvPi2VFng+4\n" +
                "hXds41goc3F49m7lnsKD9bMVEKDwDugcHx3VfeTT4lICGLvILNLkp5noMxSHtnV6\n" +
                "N/mZvnAHHf3uE/PkXDibuJkm3LscaG85A0fQtiB1UYzm/IFVFW4K0NTHeS0UzyzZ\n" +
                "UHjkzxIW2sNziGzljpb8+As=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1anyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = ca.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid.toString() == NISTTestPolicyOne } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
    }

    "Valid Policy Mapping Test14" {
        val leafPem = "-----BEGIN CERTIFICATE-----\n" +
                "MIIDnTCCAoWgAwIBAgIBAjANBgkqhkiG9w0BAQsFADBUMQswCQYDVQQGEwJVUzEf\n" +
                "MB0GA1UEChMWVGVzdCBDZXJ0aWZpY2F0ZXMgMjAxMTEkMCIGA1UEAxMbUDFhbnlQ\n" +
                "b2xpY3kgTWFwcGluZyAxdG8yIENBMB4XDTEwMDEwMTA4MzAwMFoXDTMwMTIzMTA4\n" +
                "MzAwMFowYzELMAkGA1UEBhMCVVMxHzAdBgNVBAoTFlRlc3QgQ2VydGlmaWNhdGVz\n" +
                "IDIwMTExMzAxBgNVBAMTKlZhbGlkIFBvbGljeSBNYXBwaW5nIEVFIENlcnRpZmlj\n" +
                "YXRlIFRlc3QxNDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANJpXBTA\n" +
                "3EjsCM9UAoN4IpqwMwiEiVinUgeyznx8NNMjAkrsfSYyMGuchz7Ty/nobcdnUdnZ\n" +
                "50UodPrVCuy/Cyp/8vrseLEElc2iCsXifGYGSNqxw7906l2rVOvXPQocc0Oa6eTM\n" +
                "PeHQ//CnC3V209gER16XJ2u/cQshC5Hc6y8lnGf5JsMfcSuPn9QuWnsJt68YElOG\n" +
                "y9UKmK6fbYHUKH2lwKRGHvCU6UyXgTGnaf50Yu+X2RPe7F7tBWYangT+W6JsgBzu\n" +
                "SINOiTKjoAD4KysSn+jgFMcKQ6wLhFlb6myIFOX5c93qJ2z0pNCdBiKswpBwkxQ1\n" +
                "BM4Gu6OY0EE2hGkCAwEAAaNrMGkwHwYDVR0jBBgwFoAUHwIoKDKOSoT4uItB8V17\n" +
                "6CVSa4YwHQYDVR0OBBYEFP7baMrCM949EDtAPOIY3Qz4oLGuMA4GA1UdDwEB/wQE\n" +
                "AwIE8DAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwDQYJKoZIhvcNAQELBQADggEB\n" +
                "AK347siub9i/zLVRrZkhB/xSOaOpN/ReyvDZsgfdj9oyMHsB1J6ToViVwrx8Af2+\n" +
                "V4a+ajppbH3FK8jq38FQiUqVwNT2N9MBUuBEBIdq74bvtj7saVjpuBWyPuxV0MMq\n" +
                "X1zLln5p7KA1M1PNT4uB+g5D1a0MP6I8oPCSiFY6s5cDyzR+vPOXvf7/RXwi8rnT\n" +
                "7hXgSU1KS5gnDt4qRS+j/eQYDQFZnkH3WIdbyupTmpFLkqAIL4FuNfBOwEJWijY4\n" +
                "lvwET2SIsHPLLgtlg6lzyY+LmlJ0ABeFLxgCjPINOKj7yafvQa2G6kaAp34XU1Ms\n" +
                "C0bZ/GDrvAwewPgQM54j7lM=\n" +
                "-----END CERTIFICATE-----"

        val ca = X509Certificate.decodeFromPem(p1anyPolicyMapping1to2CACert).getOrThrow()
        val leaf = X509Certificate.decodeFromPem(leafPem).getOrThrow()
        val chain: CertificateChain = listOf(leaf, ca)

        shouldNotThrow<Throwable> {
            val validationResult = chain.validate(defaultContext)
            val qualifiers = validationResult.rootPolicyNode?.getAllSubtreeQualifiers()
            qualifiers?.size shouldBe 1

            val displayedQualifier = qualifiers?.first()?.qualifier as Qualifier.UserNotice
            val expectedQualifier = ca.findExtension<CertificatePoliciesExtension>()
                ?.certificatePolicies
                ?.first { it.oid == KnownOIDs.anyPolicy } // Verify whether the given qualifier is correctly associated with the specified policy
                ?.policyQualifiers?.first()
                ?.qualifier as Qualifier.UserNotice
            displayedQualifier.explicitText?.value shouldBe expectedQualifier.explicitText?.value
        }
    }
})