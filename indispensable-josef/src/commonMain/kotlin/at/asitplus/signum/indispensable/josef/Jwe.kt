package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.catching
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.josef.io.joseCompliantSerializer
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.InternalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.PolymorphicKind
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Wrapper for all JWE formats.
 */
@Serializable(with = JweSerializer::class)
sealed class JWE : JsonSecured {

    suspend inline fun <reified P> getPayload(
        noinline decryptor: decryptorFun,
    ): KmmResult<P> = catching {
        joseCompliantSerializer.decodeFromString<P>(decryptor(this).decodeToString())
    }

    inline fun <reified A> getAdditionalAuthenticatedData(): KmmResult<A?> = catching {
        when (this) {
            is JweCompact -> null
            is JweGeneral -> additionalAuthenticatedData
            is JweFlattened -> additionalAuthenticatedData
        }?.decodeToString()?.let {
            joseCompliantSerializer.decodeFromString<A>(it)
        }
    }

    object SerialNames {
        const val PROTECTED = "protected"
        const val UNPROTECTED = "unprotected"
        const val HEADER = "header"
        const val RECIPIENTS = "recipients"
        const val ENCRYPTED_KEY = "encrypted_key"
        const val AAD = "aad"
        const val INITIALIZATION_VECTOR = "iv"
        const val CIPHERTEXT = "ciphertext"
        const val AUTHENTICATION_TAG = "tag"

        /* Shapes */
        const val COMPACT = "compact"
        const val FLATTENED = "flattened"
        const val GENERAL = "general"
    }

    companion object {
        fun getEncodedProtectedHeader(protectedHeader: ByteArray?): String =
            protectedHeader?.encodeToString(Base64UrlStrict).orEmpty()

        /**
         * Builds the RFC 7516 Additional Authenticated Data input from the protected header and optional JWE AAD.
         */
        fun getAdditionalAuthenticatedData(
            protectedHeader: ByteArray?,
            additionalAuthenticatedData: ByteArray?
        ): ByteArray {
            val encodedProtectedHeader = getEncodedProtectedHeader(protectedHeader)
            return if (additionalAuthenticatedData == null) {
                encodedProtectedHeader.encodeToByteArray()
            } else {
                "$encodedProtectedHeader.${additionalAuthenticatedData.encodeToString(Base64UrlStrict)}".encodeToByteArray()
            }
        }
    }
}
