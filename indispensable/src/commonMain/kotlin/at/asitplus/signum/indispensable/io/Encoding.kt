package at.asitplus.signum.indispensable.io

import at.asitplus.awesn1.BERTags
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromDer
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.misc.ANSIECPrefix
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.sign.ECDSAPublicKey
import at.asitplus.signum.indispensable.sign.RSAPublicKey
import io.matthewnelson.encoding.base64.Base64
import io.matthewnelson.encoding.base64.Base64ConfigBuilder
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.listSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import at.asitplus.awesn1.crypto.pki.X509Certificate as Awesn1X509Certificate

/** Strict Base64 URL encode */
val Base64UrlStrict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = true
    isLenient = true
    padEncoded = false
}.build())


/** Strict Base64 encoder */
val Base64Strict = Base64(config = Base64ConfigBuilder().apply {
    lineBreakInterval = 0
    encodeToUrlSafe = false
    isLenient = true
    padEncoded = true
}.build())

sealed class TemplateSerializer<T>(serialName: String = "") : KSerializer<T> {
    protected val realSerialName =
        serialName.ifEmpty { this::class.simpleName
            ?: throw IllegalArgumentException("Anonymous classes must specify a serialName explicitly") }
}

open class TransformingSerializerTemplate<ValueT, EncodedT>
    (private val parent: KSerializer<EncodedT>, private val encodeAs: (ValueT)->EncodedT,
     private val decodeAs: (EncodedT)->ValueT, serialName: String = "")
    : TemplateSerializer<ValueT>(serialName) {

    override val descriptor: SerialDescriptor =
        when (val kind = parent.descriptor.kind) {
            is PrimitiveKind -> PrimitiveSerialDescriptor(realSerialName, kind)
            else -> SerialDescriptor(realSerialName, parent.descriptor)
        }

    override fun serialize(encoder: Encoder, value: ValueT) {
        val v = try { encodeAs(value) }
        catch (x: Throwable) { throw SerializationException("Encoding failed", x) }
        encoder.encodeSerializableValue(parent, v)
    }

    override fun deserialize(decoder: Decoder): ValueT {
        val v = decoder.decodeSerializableValue(parent)
        try { return decodeAs(v) }
        catch (x: Throwable) { throw SerializationException("Decoding failed", x) }
    }
}

/** De-/serializes Base64 strings to/from [ByteArray] */
object ByteArrayBase64Serializer : TransformingSerializerTemplate<ByteArray, String>(
    parent = String.serializer(),
    encodeAs = { it.encodeToString(Base64Strict) },
    decodeAs = { it.decodeToByteArray(Base64Strict) }
)

/** De-/serializes Base64Url strings to/from [ByteArray] */
object ByteArrayBase64UrlSerializer : TransformingSerializerTemplate<ByteArray, String>(
    parent = String.serializer(),
    encodeAs = { it.encodeToString(Base64UrlStrict) },
    decodeAs = { it.decodeToByteArray(Base64UrlStrict) }
)

/** De-/serializes Base64Url strings to/from [ByteArray] rejecting padded strings for protocols that require unpadded Base64Url such as RFC7515 */
object ByteArrayBase64UrlNoPaddingSerializer : TransformingSerializerTemplate<ByteArray, String>(
    parent = String.serializer(),
    encodeAs = { it.encodeToString(Base64UrlStrict) },
    decodeAs = {
        require(!it.contains("=")) { "Trailing = are not supported" }
        it.decodeToByteArray(Base64UrlStrict)
    }
)

/** De-/serializes X509Certificate as Base64Url-encoded String */
object X509CertificateBase64UrlSerializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = ::encodeX509CertificateToDer,
    decodeAs = ::decodeX509CertificateFromDer // workaround iOS compilation bug KT-71498
)

/** De-/serializes X509Certificate as Base64-encoded String */
object X509CertificateBase64Serializer : TransformingSerializerTemplate<Certificate, ByteArray>(
    parent = ByteArrayBase64Serializer,
    encodeAs = ::encodeX509CertificateToDer,
    decodeAs = ::decodeX509CertificateFromDer // workaround iOS compilation bug KT-71498
)

private fun encodeX509CertificateToDer(certificate: Certificate): ByteArray = certificate.encodeToDer()

private fun decodeX509CertificateFromDer(src: ByteArray): Certificate =
    Certificate(DER.decodeFromDer<Awesn1X509Certificate>(src))

/** De-/serializes a public key as a Base64Url-encoded IOS encoding public key */
object IosPublicKeySerializer : TransformingSerializerTemplate<CryptoPublicKey, ByteArray>(
    parent = ByteArrayBase64UrlSerializer,
    encodeAs = CryptoPublicKey::iosEncoded,
    // TODO: medium term this needs to be replaced with a more sensible encoding
    //  but it needs to stay in sync with clients (cycle type identifier etc)
    decodeAs = { when (it[0].toUByte()) {
        ANSIECPrefix.UNCOMPRESSED.prefixUByte ->
            ECDSAPublicKey.fromIosEncoded(it)
        (BERTags.SEQUENCE or BERTags.CONSTRUCTED) ->
            RSAPublicKey.fromIosEncoded(it)
        else -> throw IllegalArgumentException("Unknown iOS Key type")
    }})

sealed class ListSerializerTemplate<ValueT>(
    using: KSerializer<ValueT>, serialName: String = "")
    : TemplateSerializer<List<ValueT>>(serialName) {

    override val descriptor: SerialDescriptor =
        SerialDescriptor(realSerialName, listSerialDescriptor(using.descriptor))

    private val realSerializer = ListSerializer(using)
    override fun serialize(encoder: Encoder, value: List<ValueT>) =
        encoder.encodeSerializableValue(realSerializer, value)

    override fun deserialize(decoder: Decoder): List<ValueT> =
        decoder.decodeSerializableValue(realSerializer)

}

/** De-/serializes X509Certificate as collection of Base64Url-encoded Strings */
object CertificateChainBase64UrlSerializer : ListSerializerTemplate<Certificate>(
    using = X509CertificateBase64UrlSerializer)

/** De-/serializes X509Certificate as collection of Base64-encoded Strings */
object CertificateChainBase64Serializer : ListSerializerTemplate<Certificate>(
    using = X509CertificateBase64Serializer)
