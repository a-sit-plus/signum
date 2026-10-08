package at.asitplus.signum.examples

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.awesn1.serialization.encodeToTlv
import at.asitplus.signum.dsl.ec
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.Signer
import at.asitplus.signum.indispensable.sign.sign
import at.asitplus.signum.supreme.installSupreme
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

val MigrationExamples by matrixSuite {
    "Semantic CSR and custom ASN.1 builder" {
        Signum.installSupreme()
        val signer = Signer.Ephemeral { ec { } }
        // --8<-- [start:migration-csr]
        val subject = X500Name.fromString("CN=Attestation client")
        val attribute = CsrAttribute(ObjectIdentifier("1.3.6.1.4.1.55555.3"), Asn1String.UTF8("proof").encodeToTlv())
        val tbsCsr = TbsCertificationRequest(subject, signer.publicKey, attributes = listOf(attribute))
        val csr = signer.sign(tbsCsr)
        val encoded = Signum.Der.encodeToByteArray(csr)
        val decoded = Signum.Der.decodeFromByteArray<CertificationRequest>(encoded)
        val envelope = Asn1.Sequence { +Signum.Der.encodeToTlv(decoded) }
        // --8<-- [end:migration-csr]
        decoded.tbsCsr shouldBe tbsCsr
        envelope.children.single() shouldBe Signum.Der.encodeToTlv(csr)
    }
}
