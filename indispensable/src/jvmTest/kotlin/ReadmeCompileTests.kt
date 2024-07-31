import at.asitplus.signum.indispensable.asn1.Asn1
import at.asitplus.signum.indispensable.asn1.Asn1.PrintableString
import at.asitplus.signum.indispensable.asn1.Asn1.Tagged
import at.asitplus.signum.indispensable.asn1.Asn1.UtcTime
import at.asitplus.signum.indispensable.asn1.Asn1.Utf8String
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.BERTags
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.compilation.shouldCompile
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant

class ReadmeCompileTests : FreeSpec({
    "!Certificate Parsing" {

        """
val cert = X509Certificate.decodeFromDer(certBytes)

when (val pk = cert.publicKey) {
    is CryptoPublicKey.EC -> println(
        "Certificate with serial no. %{
            cert.tbsCertificate.serialNumber
        } contains an EC public key using curve %{pk.curve}"
    )

    is CryptoPublicKey.Rsa -> println(
        "Certificate with serial no. %{
            cert.tbsCertificate.serialNumber
        } contains a %{pk.bits.number} bit RSA public key"
    )
}

println("The full certificate is:\n%{Json { prettyPrint = true }.encodeToString(cert)}")

println("Re-encoding it produces the same bytes? %{cert.encodeToDer() contentEquals certBytes}")
""".replace('%','$').shouldCompile()
    }

    "!Creating a CSR" {
        """
val ecPublicKey: ECPublicKey = TODO("From platform-specific code")
val cryptoPublicKey = CryptoPublicKey.EC.fromJcaPublicKey(ecPublicKey).getOrThrow()

val commonName = "DefaultCryptoService"
val signatureAlgorithm = X509SignatureAlgorithm.ES256


val tbsCsr = TbsCertificationRequest(
    version = 0,
    subjectName = listOf(RelativeDistinguishedName(AttributeTypeAndValue.CommonName(Asn1String.UTF8(commonName)))),
    publicKey = cryptoPublicKey
)
val signed: ByteArray = TODO("pass tbsCsr.encodeToDer() to platform code")
val csr = Pkcs10CertificationRequest(tbsCsr, signatureAlgorithm, signed)

println(csr.encodeToDer())
""".shouldCompile()
    }

    "!ASN1 DSL for Creating ASN.1 Structures" {
        """
Asn1.Sequence {
    +Tagged(1u) {
        +Asn1Primitive(BERTags.BOOLEAN, byteArrayOf(0x00))
    }
    +Asn1.Set {
        +Asn1.Sequence {
            +Asn1.SetOf {
                +PrintableString("World")
                +PrintableString("Hello")
            }
            +Asn1.Set {
                +PrintableString("World")
                +PrintableString("Hello")
                +Utf8String("!!!")
            }

        }
    }
    +Asn1.Null()

    +ObjectIdentifier("1.2.603.624.97")

    +Utf8String("Foo")
    +PrintableString("Bar")

    +Asn1.Set {
        +Asn1.Int(3)
        +Asn1.Long(-65789876543L)
        +Asn1.Bool(false)
        +Asn1.Bool(true)
    }
    +Asn1.Sequence {
        +Asn1.Null()
        +Asn1String.Numeric("12345")
        +UtcTime(Clock.System.now())
    }
}
""".shouldCompile()
    }
})
