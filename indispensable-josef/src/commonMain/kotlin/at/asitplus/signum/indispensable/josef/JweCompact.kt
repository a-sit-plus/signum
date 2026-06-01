package at.asitplus.signum.indispensable.josef

import at.asitplus.signum.indispensable.io.Base64UrlStrict
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.Transient
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Implements compact serialization as defined in RFC 7516.
 *
 * Serialized output is:
 * BASE64URL(UTF8(PROTECTED)).BASE64URL(ENCRYPTED_KEY).BASE64URL(IV).BASE64URL(CIPHERTEXT).BASE64URL(TAG)
 */
@ConsistentCopyVisibility
data class JweCompact internal constructor(
    val plainProtectedHeader: ByteArray,
    val encryptedKey: ByteArray? = null,
    val initializationVector: ByteArray? = null,
    val ciphertext: ByteArray,
    val authenticationTag: ByteArray? = null,
) : JWE() {

    @Transient
    val jweHeader: JweHeader = JweHeader.fromParts(plainProtectedHeader, null, null)

    @Transient
    val additionalAuthenticatedData: ByteArray = getAdditionalAuthenticatedData(plainProtectedHeader, null)

    override fun toString() = "${plainProtectedHeader.encodeToString(Base64UrlStrict)}." +
            "${encryptedKey?.encodeToString(Base64UrlStrict).orEmpty()}." +
            "${initializationVector?.encodeToString(Base64UrlStrict).orEmpty()}." +
            "${ciphertext.encodeToString(Base64UrlStrict)}." +
            authenticationTag?.encodeToString(Base64UrlStrict).orEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as JweCompact

        if (!plainProtectedHeader.contentEquals(other.plainProtectedHeader)) return false
        if (!encryptedKey.contentEquals(other.encryptedKey)) return false
        if (!initializationVector.contentEquals(other.initializationVector)) return false
        if (!ciphertext.contentEquals(other.ciphertext)) return false
        if (!authenticationTag.contentEquals(other.authenticationTag)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = plainProtectedHeader.contentHashCode()
        result = 31 * result + (encryptedKey?.contentHashCode() ?: 0)
        result = 31 * result + (initializationVector?.contentHashCode() ?: 0)
        result = 31 * result + ciphertext.contentHashCode()
        result = 31 * result + (authenticationTag?.contentHashCode() ?: 0)
        return result
    }

    companion object {
        /**
         * Build a [JweCompact] received as compact serialization string.
         */
        operator fun invoke(base64UrlString: String): JweCompact {
            require(!base64UrlString.contains("=")) { "Trailing = are not supported. See RFC 7516" }
            val partCount = base64UrlString.count { it == '.' } + 1
            if (partCount != 5) {
                throw SerializationException(
                    "Invalid JWE compact serialization: expected 5 parts, got $partCount"
                )
            }
            val parts = base64UrlString.split('.', limit = 5)

            return try {
                JweCompact(
                    plainProtectedHeader = parts[0].decodeToByteArray(Base64UrlStrict),
                    encryptedKey = parts[1].decodeOptionalBase64UrlSegment(),
                    initializationVector = parts[2].decodeOptionalBase64UrlSegment(),
                    ciphertext = parts[3].decodeToByteArray(Base64UrlStrict),
                    authenticationTag = parts[4].decodeOptionalBase64UrlSegment(),
                )
            } catch (e: Exception) {
                throw SerializationException("Invalid base64url content in JWE compact serialization", e)
            }
        }

        /**
         * Build a compact JWE from components.
         */
        suspend operator fun <P> invoke(
            protectedHeader: JweHeader,
            payload: P,
            additionalAuthenticatedData: ByteArray? = null,
            encryptor: suspend (JweHeader.Part, P) -> EncryptionOutput,
        ): JweCompact {
            val plainProtectedHeader = JweProtectedHeaderSerializer.encodeToByteArray(protectedHeader.toPart())
            val encryptionOutput = encryptor(protectedHeader.toPart(), payload)
            return JweCompact(
                plainProtectedHeader = plainProtectedHeader,
                encryptedKey = encryptionOutput.encryptedKey.takeUnlessEmpty(),
                initializationVector = encryptionOutput.iv.takeUnlessEmpty(),
                ciphertext = encryptionOutput.cipherText,
                authenticationTag = encryptionOutput.authenticationTag.takeUnlessEmpty(),
            )
        }
    }
}

/**
 * Serializes a [JweCompact] as its compact JWE string form inside JSON.
 */
object JweCompactStringSerializer : KSerializer<JweCompact> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("JweCompact", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweCompact) = encoder.encodeString(value.toString())

    override fun deserialize(decoder: Decoder): JweCompact = JweCompact(decoder.decodeString())
}

val JweCompact.protectedHeader: JweHeader.Part
    get() = JweProtectedHeaderSerializer.decodeFromByteArray(plainProtectedHeader)

/**
 * Converts compact serialization to the equivalent flattened JSON form.
 */
fun JweCompact.toJweFlattened(): JweFlattened = JweFlattened(
    plainProtectedHeader = plainProtectedHeader,
    sharedUnprotectedHeader = null,
    recipientUnprotectedHeader = null,
    encryptedKey = encryptedKey,
    additionalAuthenticatedData = null,
    initializationVector = initializationVector,
    ciphertext = ciphertext,
    authenticationTag = authenticationTag,
)

private fun String.decodeOptionalBase64UrlSegment(): ByteArray? =
    takeUnless { it.isEmpty() }?.decodeToByteArray(Base64UrlStrict)
