import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.getJcaPublicKey
import at.asitplus.crypto.datatypes.jws.JwsSigned
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.types.shouldBeInstanceOf
import java.security.Signature

class JwsSignedTest : FreeSpec({

    "JWS can be parsed and verified" - {
        val input = """
            eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6bUVwQzNtYjJEaDZLY2FiOE1UWVJrQi9kRnlRbUk4VTZMVUs0L1gzZXlSalFmRG1ZdDJJ
            aDB1VWpZMno5enIvYjNoT1IvTDhwa0JGZXRqNUUyYTJHQXlyREEiLCJ0eXAiOiJrYitqd3QifQ.eyJpYXQiOjE3MDI1NjE2OTAsImF1ZCI6I
            mRpZDprZXk6bUVwQzhtWWR1ajcrc3BKd2dUY01TeUw1ZkFxcTFtOS92OGFnd1VuQzZIVTFDKzIra2FUdFRLelN6bXVjb3RtWTdiTWFtSGEvb
            m90cjlPMDB3Wi8rR0tpeDAiLCJub25jZSI6Ijc1N2M2NmQwLTMwN2MtNDhjZC1iZGRiLTU3MmIyMWQxNzYxNiJ9.Xf-5dG7Bk5A4VnigYdA5
            NKpH2D9EzAhfckXCKleKHsTDyudswCU3pTaw2jYxafPX68X6QMnvlk14evw_kI8O9Q
        """.trimIndent()

        val parsed = JwsSigned.parse(input)
        parsed.shouldNotBeNull()

        val publicKey = parsed.header.publicKey
        publicKey.shouldNotBeNull()
        publicKey.shouldBeInstanceOf<CryptoPublicKey.Ec>()
        val jcaKey = publicKey.getJcaPublicKey().getOrThrow()
        val asn1Signature = parsed.signature.encodeToDer()
        val signatureInput = parsed.plainSignatureInput.encodeToByteArray()

        val result = Signature.getInstance("SHA256withECDSA").apply {
            initVerify(jcaKey)
            update(signatureInput)
        }.verify(asn1Signature)
        result.shouldBeTrue()
    }

})
