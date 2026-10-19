package at.asitplus.signum.indispensable.cosef

import at.asitplus.signum.indispensable.cosef.io.Base16Strict
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.Serializable

internal fun ByteArray.hex(): String = encodeToString(Base16Strict).uppercase()

internal fun String.hexBytes(): ByteArray = decodeToByteArray(Base16())

/** Payload of the RFC 9052 examples. */
internal val CONTENT: ByteArray get() = "This is the content.".encodeToByteArray()
internal const val CONTENT_HEX = "546869732069732074686520636F6E74656E742E"

/** `{1: -7}` */
internal val ES256_HEADER = CoseHeader(algorithm = CoseAlgorithm.Signature.ES256)
internal const val ES256_HEADER_HEX = "A10126"

/** `{1: -257}`. */
internal val RS256_HEADER = CoseHeader(algorithm = CoseAlgorithm.Signature.RS256)
internal const val RS256_HEADER_HEX = "A101390100"

/** `{1: 5}` */
internal val HS256_HEADER = CoseHeader(algorithm = CoseAlgorithm.MAC.HS256)
internal const val HS256_HEADER_HEX = "A10105"

internal val FAKE_SIGNATURE: ByteArray get() = "bar".encodeToByteArray()
internal val FAKE_TAG: ByteArray get() = "tag".encodeToByteArray()
internal val EXTERNAL_AAD: ByteArray get() = "11AA22BB33CC44DD55006699".hexBytes()

@Serializable
internal data class CoseTestPayload(val name: String, val count: Int)