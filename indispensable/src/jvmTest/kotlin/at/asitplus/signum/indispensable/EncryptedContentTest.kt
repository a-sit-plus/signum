package at.asitplus.signum.indispensable

import at.asitplus.signum.indispensable.asn1.Asn1
import at.asitplus.signum.indispensable.pki.cms.AuthEnvelopedData
import at.asitplus.signum.indispensable.pki.cms.EncryptedContentInfo
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import kotlin.random.Random

class EncryptedContentTest:FreeSpec( {

    "DER Encoding/Decoding works" {
        val content = AuthEnvelopedData(EncryptedContentInfo(Asn1.Sequence { +Asn1.Int(1337) },Random.nextBytes(1337)),Random.nextBytes(42))

        AuthEnvelopedData.decodeFromDer(content.encodeToDer()) shouldBe content
    }

})