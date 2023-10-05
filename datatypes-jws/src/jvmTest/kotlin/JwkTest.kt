import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.fromJcaKey
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.jws.jwkId
import at.asitplus.crypto.datatypes.jws.toJsonWebKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey

class JwkTest : FreeSpec({
    "EC" - {

        withData(256, 384, 521) { bits ->
            val keys = List<ECPublicKey>(10) {
                val ecKp = KeyPairGenerator.getInstance("EC").apply {
                    initialize(bits)
                }.genKeyPair()
                ecKp.public as ECPublicKey
            }
            withData(
                nameFn = {
                    "(x: ${
                        it.w.affineX.toByteArray().encodeToString(Base64Strict)
                    } y: ${it.w.affineY.toByteArray().encodeToString(Base64Strict)})"
                },
                keys
            ) { pubKey ->

                val cryptoPubKey = CryptoPublicKey.Ec.fromJcaKey(pubKey)!!
                val own = cryptoPubKey.toJsonWebKey()
                own.keyId shouldBe cryptoPubKey.jwkId
                own.shouldNotBeNull()
                println(own.serialize())
                own.toAnsiX963ByteArray()
                    .fold(onSuccess = { it shouldBe cryptoPubKey.iosEncoded }, onFailure = { throw it })

                CryptoPublicKey.fromKeyId(own.keyId!!) shouldBe cryptoPubKey
            }
        }
    }
})