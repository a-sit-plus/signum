package at.asitplus.crypto.datatypes.jws

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.AESEncrypter
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe
import javax.crypto.KeyGenerator
import kotlin.random.Random


class JweEncryptedTest : FreeSpec({

    "Minimal JWE can be parsed and verified" - {
        val input = Random.Default.nextBytes(32)

        val nimbusHeader = JWEHeader.Builder(
            JWEAlgorithm.A128KW, EncryptionMethod.A128GCM
        ).build()
        val jweNimbus = JWEObject(
            nimbusHeader,
            Payload(input)
        )

        val secretKey = KeyGenerator.getInstance("AES").apply { init(128) }.generateKey()
        jweNimbus.encrypt(AESEncrypter(secretKey))

        val parsed = JweEncrypted.parse(jweNimbus.serialize()).getOrThrow()

        //val header = parsed.header.shouldNotBeNull()
        val header = JweHeader.deserialize(parsed.headerAsParsed.decodeToString()).getOrThrow()
        header.algorithm shouldBe JweAlgorithm.A128KW
        header.encryption shouldBe JweEncryption.A128GCM
        parsed.ciphertext shouldBe jweNimbus.cipherText.decode()
    }
})
