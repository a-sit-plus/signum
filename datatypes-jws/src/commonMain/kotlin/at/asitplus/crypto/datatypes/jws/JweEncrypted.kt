package at.asitplus.crypto.datatypes.jws

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.io.Base64Strict
import at.asitplus.crypto.datatypes.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString

/**
 * Representation of an encrypted JSON Web Encryption object, consisting of its 5 parts: Header, encrypted key,
 * IV, ciphertext, authentication tag.
 *
 * See [RFC 7516](https://datatracker.ietf.org/doc/html/rfc7516)
 *
 * @see [JweDecrypted]
 */
data class JweEncrypted(
    val headerAsParsed: ByteArray,
    val encryptedKey: ByteArray? = null,
    val iv: ByteArray,
    val ciphertext: ByteArray,
    val authTag: ByteArray
) {
    val header: JweHeader?
        get() = JweHeader.deserialize(headerAsParsed.decodeToString()).getOrNull()

    fun serialize(): String {
        return headerAsParsed.encodeToString(Base64UrlStrict) +
                ".${encryptedKey?.encodeToString(Base64UrlStrict) ?: ""}" +
                ".${iv.encodeToString(Base64UrlStrict)}" +
                ".${ciphertext.encodeToString(Base64UrlStrict)}" +
                ".${authTag.encodeToString(Base64UrlStrict)}"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweEncrypted

        if (!headerAsParsed.contentEquals(other.headerAsParsed)) return false
        if (encryptedKey != null) {
            if (other.encryptedKey == null) return false
            if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        } else if (other.encryptedKey != null) return false
        if (!iv.contentEquals(other.iv)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authTag.contentEquals(other.authTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = headerAsParsed.contentHashCode()
        result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
        result = 31 * result + iv.contentHashCode()
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + authTag.contentHashCode()
        return result
    }


    companion object {
        fun parse(it: String): KmmResult<JweEncrypted> = runCatching {
            val stringList = it.replace("[^A-Za-z0-9-_.]".toRegex(), "").split(".")
            if (stringList.size != 5) throw IllegalArgumentException("not five parts in input: $it")
            val headerAsParsed = stringList[0].decodeToByteArray(Base64Strict)
            val encryptedKey = stringList[1].decodeToByteArray(Base64Strict)
            val iv = stringList[2].decodeToByteArray(Base64Strict)
            val ciphertext = stringList[3].decodeToByteArray(Base64Strict)
            val authTag = stringList[4].decodeToByteArray(Base64Strict)
            JweEncrypted(headerAsParsed, encryptedKey, iv, ciphertext, authTag)
        }.wrap()
    }
}