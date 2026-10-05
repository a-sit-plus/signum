package at.asitplus.signum.indispensable

import at.asitplus.signum.Signum

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.Pkcs10CertificationRequest
import at.asitplus.awesn1.crypto.pki.X509Certificate
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificationRequest
import at.asitplus.signum.indispensable.pki.asn1Representation
import at.asitplus.signum.indispensable.sign.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.serializer
import kotlin.reflect.KClass
import kotlin.reflect.typeOf

/** PEM framing for Signum.Der; see docs/docs/default-der.md. */
inline fun <reified T : Encodable> Der.encodeToPemBlock(value: T): PemBlock {
    // Nested codecs use Signum.Der, so PEM must use that same instance (docs/docs/default-der.md).
    require(this === Signum.Der) { "Use Signum.Der for Signum PEM serialization" }
    val model = when (value) {
        is Certificate -> value.asn1Representation
        is CertificationRequest -> value.asn1Representation
        is CryptoPublicKey -> value.asn1Representation
        is CryptoPrivateKey -> value.asn1Representation
        else -> value.representations[at.asitplus.signum.indispensable.pki.X509]
    }
    val label = (model as? WithPemLabel)?.pemLabel
        ?: throw IllegalArgumentException("${T::class.simpleName} has no PEM label")
    return PemBlock(label, payload = encodeToByteArray(value))
}

inline fun <reified T : Encodable> Der.encodeToPem(value: T): String = encodeToPemBlock(value).encodeToPem()

inline fun <reified T : Encodable> Der.decodeFromPemBlock(
    source: PemBlock,
    limit: Long = source.payload.size.toLong(),
): T {
    // Nested codecs use Signum.Der, so PEM must use that same instance (docs/docs/default-der.md).
    require(this === Signum.Der) { "Use Signum.Der for Signum PEM serialization" }
    return decodeSignumPem(T::class, configuration.serializersModule.serializer(typeOf<T>()) as KSerializer<T>, source, limit)
}

inline fun <reified T : Encodable> Der.decodeFromPem(source: String, limit: Long? = null): T =
    PemBlock.decodeFromPem(source).let { decodeFromPemBlock(it, limit ?: it.payload.size.toLong()) }

@PublishedApi
internal fun <T : Encodable> Der.decodeSignumPem(
    type: KClass<T>, serializer: KSerializer<T>, source: PemBlock, limit: Long,
): T {
    require(!source.headers.any()) { "Unexpected PEM headers are present in the data" }
    require(source.payload.size.toLong() <= minOf(limit, configuration.maxInputLength)) { "PEM payload exceeds input limit" }
    val spec = when (type) {
        Certificate::class -> X509Certificate
        CertificationRequest::class -> Pkcs10CertificationRequest
        CryptoPublicKey::class, EcdsaPublicKey::class, RsaPublicKey::class -> SubjectPublicKeyInfo
        CryptoPrivateKey::class, CryptoPrivateKey.WithPublicKey::class, RsaPrivateKey::class,
        EcdsaPrivateKey::class, EcdsaPrivateKey.WithPublicKey::class, EcdsaPrivateKey.WithoutPublicKey::class -> Pkcs8PrivateKeyInfo
        else -> throw IllegalArgumentException("${type.simpleName} has no PEM label")
    }
    // Algorithm-specific types accept only their own alternative labels.
    when (type) {
        EcdsaPublicKey::class -> require(source.pemLabel != Pkcs1RsaPublicKeyInfo.PEM_LABEL) { "Expected EC public key" }
        RsaPrivateKey::class -> require(source.pemLabel != Sec1EcPrivateKeyInfo.PEM_LABEL) { "Expected RSA private key" }
        EcdsaPrivateKey::class, EcdsaPrivateKey.WithPublicKey::class, EcdsaPrivateKey.WithoutPublicKey::class ->
            require(source.pemLabel != Pkcs1RsaPrivateKeyInfo.PEM_LABEL) { "Expected EC private key" }
    }
    spec.validate(source)
    val alternate: Encodable? = when (source.pemLabel) {
        Pkcs1RsaPublicKeyInfo.PEM_LABEL -> decodeFromByteArray(Pkcs1RsaPublicKeyInfo.serializer(), source.payload)
            .let { RsaPublicKey(it.modulus, it.publicExponent) }
        Pkcs1RsaPrivateKeyInfo.PEM_LABEL -> RsaPrivateKey.fromAsn1Representation(decodeFromByteArray(Pkcs1RsaPrivateKeyInfo.serializer(), source.payload))
        Sec1EcPrivateKeyInfo.PEM_LABEL -> EcdsaPrivateKey.fromAsn1Representation(decodeFromByteArray(Sec1EcPrivateKeyInfo.serializer(), source.payload))
        else -> null
    }
    if (alternate == null) return decodeFromByteArray(serializer, source.payload)
    require(type.isInstance(alternate)) { "PEM key cannot be decoded as ${type.simpleName}" }
    @Suppress("UNCHECKED_CAST")
    return alternate as T
}
