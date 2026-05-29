package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.supreme.asymmetric.HPKE.Mode
import at.asitplus.signum.supreme.asymmetric.HPKETestSuite.Export
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.fail
import io.kotest.assertions.withClue
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive

private fun JsonObject.requireInt(k: String) = this[k]!!.jsonPrimitive.int
private fun JsonObject.hexBytesOrNull(k: String) =
    this[k]?.jsonPrimitive?.let { require (it.isString); it.content }?.hexToByteArray()
private fun JsonObject.requireHexBytes(k: String) =
    hexBytesOrNull(k)!!

private inline fun <reified K: JsonElement, T> JsonObject.requireSubObjects(k: String, crossinline ctor: (K)->T) =
    this[k]!!.jsonArray.asSequence().map { ctor(it as K) }
private val WELL_KNOWN_KDFS = sequenceOf(
    HPKE.KDF.HKDF_SHA256,
    HPKE.KDF.HKDF_SHA384,
    HPKE.KDF.HKDF_SHA512)
private val WELL_KNOWN_KEMS = sequenceOf(
    HPKE.KEM.DHKEM_P256_HKDF_SHA256,
    HPKE.KEM.DHKEM_P384_HKDF_SHA384,
    HPKE.KEM.DHKEM_P521_HKDF_SHA512)
private val WELL_KNOWN_AEADS = sequenceOf(
    HPKE.AEAD.AES_128_GCM,
    HPKE.AEAD.AES_256_GCM,
    HPKE.AEAD.CHACHA20POLY1305,
    HPKE.AEAD.EXPORT_ONLY)
class HPKETestSuite(jsonObject: JsonObject) {
    companion object {
        fun shouldSkip(jsonObject: JsonObject): Boolean {
            if (jsonObject.requireInt("kem_id") in sequenceOf(0x0020, 0x0021)) return true
            return false
        }
    }
    val mode = jsonObject.requireInt("mode").let { i ->
        HPKE.Mode.entries.firstOrNull { it.mode_id.toInt() == i }
            ?: fail("Unknown HPKE mode $i")
    }
    val kem = jsonObject.requireInt("kem_id").let { i ->
        WELL_KNOWN_KEMS.firstOrNull { it.kem_id == i }
            ?: fail("Unknown KEM $i")
    }
    val kdf = jsonObject.requireInt("kdf_id").let { i ->
        WELL_KNOWN_KDFS.firstOrNull { it.kdf_id == i }
            ?: fail("Unknown KDF $i")
    }
    val aead = jsonObject.requireInt("aead_id").let { i ->
        WELL_KNOWN_AEADS.firstOrNull { it.aead_id == i }
            ?: fail("Unknown AEAD $i")
    }
    val info = jsonObject.requireHexBytes("info")
    val ikmR = jsonObject.requireHexBytes("ikmR")
    val ikmE = jsonObject.requireHexBytes("ikmE")
    val skRm = jsonObject.requireHexBytes("skRm")
    val skSm = jsonObject.hexBytesOrNull("skSm")
    val skEm = jsonObject.requireHexBytes("skEm")
    val psk = jsonObject.hexBytesOrNull("psk")
    val psk_id = jsonObject.hexBytesOrNull("psk_id")
    val pkRm = jsonObject.requireHexBytes("pkRm")
    val pkEm = jsonObject.requireHexBytes("pkEm")
    val pkSm = jsonObject.hexBytesOrNull("pkSm")
    val enc = jsonObject.requireHexBytes("enc")
    val shared_secret = jsonObject.requireHexBytes("shared_secret")
    val key_schedule_context = jsonObject.requireHexBytes("key_schedule_context")
    val secret = jsonObject.requireHexBytes("secret")
    val key = jsonObject.requireHexBytes("key")
    val base_nonce = jsonObject.requireHexBytes("base_nonce")
    val exporter_secret = jsonObject.requireHexBytes("exporter_secret")
    val encryptions = jsonObject.requireSubObjects("encryptions", ::Encryption)
    val exports = jsonObject.requireSubObjects("exports", ::Export)

    class Encryption(jsonObject: JsonObject) {
        val aad = jsonObject.requireHexBytes("aad")
        val ct = jsonObject.requireHexBytes("ct")
        val nonce = jsonObject.requireHexBytes("nonce")
        val pt = jsonObject.requireHexBytes("pt")
    }

    class Export(jsonObject: JsonObject) {
        val exporter_context = jsonObject.requireHexBytes("exporter_context")
        val L = jsonObject.requireInt("L").let(BitLength::fromBytes)
        val exported_value = jsonObject.requireHexBytes("exported_value")
    }
}
val HPKETests by testSuite {
    val tests = javaClass.getResourceAsStream("/hpke/test-vectors.json").use {
        Json.decodeFromStream<JsonArray>(it!!)
    }.asSequence().map { it as JsonObject }.filterNot(HPKETestSuite::shouldSkip).map(::HPKETestSuite)

    withData(
        nameFn={
            "mode=${it.mode.name} kem=${it.kem.kem_id} kdf=${it.kdf.kdf_id} aead=${it.aead.aead_id}"
        }, tests)
    { test ->
        val hpke = HPKE(test.kem, test.kdf, test.aead)
        if (test.mode == Mode.mode_auth || test.mode == Mode.mode_auth_psk) {
            val (shared_secret, enc) = test.kem.AuthEncap(
                test.kem.DeserializePublicKey(test.pkRm),
                test.kem.DeserializePrivateKey(test.skSm!!),
                test.ikmE
            )

            withClue("shared_secret[encap]") { shared_secret shouldBe test.shared_secret }
            withClue("enc") { enc shouldBe test.enc }
            val shared_secret_2 = test.kem.AuthDecap(
                enc,
                test.kem.DeserializePrivateKey(test.skRm),
                test.kem.DeserializePublicKey(test.pkSm!!)
            )
            withClue("shared_secret[decap]") { shared_secret_2 shouldBe test.shared_secret }
        } else {
            val (shared_secret, enc) = test.kem.Encap(
                test.kem.DeserializePublicKey(test.pkRm),
                test.ikmE
            )
            withClue("shared_secret[encap]") { shared_secret shouldBe test.shared_secret }
            withClue("enc") { enc shouldBe test.enc }
            val shared_secret_2 = test.kem.Decap(
                enc,
                test.kem.DeserializePrivateKey(test.skRm)
            )
            withClue("shared_secret[decap]") { shared_secret_2 shouldBe test.shared_secret }
        }
        val contextS = hpke.Context(test.mode, test.shared_secret, test.info, test.psk ?: byteArrayOf(), test.psk_id ?: byteArrayOf())
        val contextR = hpke.Context(test.mode, test.shared_secret, test.info, test.psk ?: byteArrayOf(), test.psk_id ?: byteArrayOf())

        test.encryptions.forEach { encryption ->
            withClue("nonce[sender]") { contextS.ComputeNonce() shouldBe encryption.nonce }
            withClue("nonce[receiver]") { contextR.ComputeNonce() shouldBe encryption.nonce }
            val ct = contextS.S().Seal(encryption.aad, encryption.pt)
            withClue("ciphertext[wrap]") { ct shouldBe encryption.ct }
            val pt = contextR.R().Open(encryption.aad, ct)
            withClue("plaintext[open]") { pt shouldBe encryption.pt }
        }

        test.exports.forEach { export ->
            withClue("export[sender]") { contextS.Export(export.exporter_context, export.L) shouldBe export.exported_value }
            withClue("export[receiver]") { contextR.Export(export.exporter_context, export.L) shouldBe export.exported_value }
        }
    }
}
