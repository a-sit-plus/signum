package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Sequence
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow

val X509CertificateStrictParsingJvmTest by testSuite {
    "TBSCertificate trailing unknown child is rejected" {
        val certPem = checkNotNull(javaClass.classLoader.getResourceAsStream("github-com.pem")) {
            "Missing github-com.pem test resource"
        }.reader().readText()
        val certDer = java.util.Base64.getMimeDecoder().decode(certPem)
        val certSeq = Asn1Element.parse(certDer) as Asn1Sequence
        val tbsSeq = certSeq.children.first() as Asn1Sequence

        val tamperedTbs = Asn1.Sequence {
            tbsSeq.children.forEach { +it }
            +Asn1.Null()
        }
        val tamperedCert = Asn1.Sequence {
            +tamperedTbs
            +certSeq.children[1]
            +certSeq.children[2]
        }.derEncoded

        shouldThrow<Throwable> {
            X509Certificate.decodeFromDer(tamperedCert)
        }
    }
}
