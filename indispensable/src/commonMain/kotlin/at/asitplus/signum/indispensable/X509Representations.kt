@file:OptIn(SignumInternals::class)

package at.asitplus.signum.indispensable

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.*
import at.asitplus.awesn1.crypto.pki.*
import at.asitplus.awesn1.io.decodeFromSource
import at.asitplus.awesn1.io.encodeToSink
import at.asitplus.awesn1.serialization.*
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.Signum
import at.asitplus.signum.SignumInternals
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Decoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1DecodersWith
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1Encoders
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.asn1EncodersWith
import at.asitplus.signum.indispensable.Asn1EncodingHelpers.withAlternativePemDecoder
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeWith
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeWith
import at.asitplus.signum.indispensable.agree.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.digest.Asn1DigestAlgorithmProvider
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.mac.Asn1MACAlgorithmProvider
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.pki.*
import at.asitplus.signum.indispensable.sign.*
import kotlinx.io.Sink
import kotlinx.io.Source
import kotlinx.serialization.KSerializer
import kotlinx.serialization.decodeFromHexString
import kotlinx.serialization.serializer
import kotlin.experimental.ExperimentalTypeInference

//// ==================================================================================
//// GENERIC CODE STARTS HERE; TOUCH *VERY* CAREFULLY (or not at all without asking me)
//// ==================================================================================

/**
 * The methods in this class are useful for extension authors that want their custom types
 * to convert from/to ASN.1 (via awesn1).
 * See the rest of this file for detailed usage examples, but very generally:
 * - `val YourType.asn1 get() = asn1Encoders { Asn1Type(...) }`
 *    gives you `asn1.toRepresentation()`, `asn1.toTlv()`, `asn1.toDer()`, etc.
 * - `val YourType.Companion.fromAsn1 get() = asn1Decoders { src: Asn1Type -> YourType(...) }`
 *    gives you `fromAsn1()` and all of its overloads (TLV, DER, etc.)
 *
 * Recommended usage is as `import ...Asn1EncodingHelpers.asn1Encoders` and
 * `import ...Asn1EncodingHelpers.asn1Decoders`.
 * Do **not** directly interface with the Impl classes.
 * Doing so is **unsupported** and will risk (among other things) breaking round trip re-encoding.
 */
object Asn1EncodingHelpers {
/** Usage:
 * - to ASN.1 type: `.asn1.toRepresentation()`
 * - to ASN.1 TLV: `asn1.toTlv()`
 * - to ASN.1 DER: `asn1.toDer()`
 */
interface Asn1Encoders<out Asn1Type: Any> {
    /** Converts the type to its ASN.1 representation. */
    fun toRepresentation(): Asn1Type
    /** Converts the type to ASN.1 TLV. */
    fun toTlv(): Asn1Element
    /** Converts the type to ASN.1 DER bytes. */
    fun toDer(): ByteArray
    /** Converts the type to ASN.1 DER and writes to the sink. */
    fun toDer(sink: Sink)

    /** Usage:
     * - to ASN.1 type: `.asn1.toRepresentation()`
     * - to ASN.1 TLV: `.asn1.toTlv()`
     * - to ASN.1 DER: `.asn1.toDer()`
     * - to ASN.1 PEM: `asn1.toPem()`
     */
    interface WithPEM<out Asn1Type: WithPemLabel> : Asn1Encoders<Asn1Type> {
        fun toPem(): String
    }
}

open class Asn1EncodersImpl<Asn1Type: Any> @SignumInternals constructor (
    private val convertingBuilder: ()->Asn1Type,
    protected val serializer: KSerializer<Asn1Type>,
) : Asn1Encoders<Asn1Type> {
    override fun toRepresentation(): Asn1Type = convertingBuilder()
    override fun toTlv(): Asn1Element = Signum.Der.encodeToTlv(serializer, toRepresentation())
    override fun toDer(): ByteArray = Signum.Der.encodeToByteArray(serializer, toRepresentation())
    override fun toDer(sink: Sink) = Signum.Der.encodeToSink(serializer, toRepresentation(), sink)
    class WithPEM<Asn1Type: WithPemLabel> @SignumInternals constructor(
        convertingBuilder: ()->Asn1Type,
        serializer: KSerializer<Asn1Type>
    ): Asn1EncodersImpl<Asn1Type>(convertingBuilder, serializer), Asn1Encoders.WithPEM<Asn1Type> {
        override fun toPem(): String = toRepresentation().encodeToPem(serializer, Signum.Der)
    }
}

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
inline fun <
    reified Asn1Type: Any,
    reified AbstractType: WithSourceRepresentation
> AbstractType.asn1Encoders(
    crossinline fn: (AbstractType)->Asn1Type
): Asn1Encoders<Asn1Type> =
    Asn1EncodersImpl(
        convertingBuilder = { this@asn1Encoders.encodeTo(fn) },
        serializer = Signum.Der.serializersModule.serializer<Asn1Type>())

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
inline fun <
    reified Asn1Type: WithPemLabel,
    reified AbstractType: WithSourceRepresentation
> AbstractType.asn1Encoders(
    crossinline fn: (AbstractType)->Asn1Type
): Asn1Encoders.WithPEM<Asn1Type> =
    Asn1EncodersImpl.WithPEM(
        convertingBuilder = { this@asn1Encoders.encodeTo(fn) },
        serializer = Signum.Der.serializersModule.serializer<Asn1Type>(),
    )

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
inline fun<
    reified ProviderType: Any,
    reified Asn1Type: Any,
    reified AbstractType: WithSourceRepresentation
> AbstractType.asn1EncodersWith(
    crossinline fn: ProviderType.(AbstractType)->Asn1Type?
): Asn1Encoders<Asn1Type> =
    Asn1EncodersImpl(
        convertingBuilder = { this@asn1EncodersWith.encodeWith(fn) },
        serializer = Signum.Der.serializersModule.serializer<Asn1Type>(),
    )

@OptIn(ExperimentalTypeInference::class)
@OverloadResolutionByLambdaReturnType
inline fun<
    reified ProviderType: Any,
    reified Asn1Type: WithPemLabel,
    reified AbstractType: WithSourceRepresentation
> AbstractType.asn1EncodersWith(
    crossinline fn: ProviderType.(AbstractType)->Asn1Type?
): Asn1Encoders.WithPEM<Asn1Type> =
    Asn1EncodersImpl.WithPEM(
        convertingBuilder = { this@asn1EncodersWith.encodeWith(fn) },
        serializer = Signum.Der.serializersModule.serializer<Asn1Type>(),
    )

/** Usage:
 * - from ASN.1 type: `fromAsn1(asn1Representation)`
 * - from ASN.1 TLV: `fromAsn1(asn1Element)`
 * - from ASN.1 DER (bytes): `fromAsn1(derEncoded)`
 * - from ASN.1 DER (hex): `fromAsn1.fromHexString(derHexBytes)`
 */
interface Asn1Decoders<in Asn1Type: Any, out AbstractType: WithSourceRepresentation>
{
    /** Parses the type from the [asn1Representation]. */
    operator fun invoke(asn1Representation: Asn1Type): AbstractType
    /** Parses the type from the TLV [Asn1Element] */
    operator fun invoke(asn1Element: Asn1Element): AbstractType
    /** Parses the type from its DER encoding */
    operator fun invoke(derBytes: ByteArray): AbstractType
    /** Parses the type from a [Source] providing its DER encoding */
    operator fun invoke(derSource: Source, limit: Long = Signum.Der.configuration.maxInputLength): AbstractType
    /** Parses the type from its hex-encoded DER encoding. */
    fun fromHexString(derHexBytes: String): AbstractType

    /** Usage:
     * - from ASN.1 type: `fromAsn1(asn1Representation)`
     * - from ASN.1 TLV: `fromAsn1(asn1Element)`
     * - from ASN.1 DER (bytes): `fromAsn1(derEncoded)`
     * - from ASN.1 DER (hex): `fromAsn1.fromHexString(derHexBytes)`
     * - from ASN.1 PEM (single): `fromAsn1(pemEncoded)`
     * - from ASN.1 PEM (multiple): `fromAsn1.list(pemEncoded)`
     */
    interface WithPEM<in Asn1Type: Any, out AbstractType: WithSourceRepresentation>
        : Asn1Decoders<Asn1Type, AbstractType> {
        /** Parses the type from its PEM encoding. */
        operator fun invoke(pemEncoded: String): AbstractType
        /** Parses multiple instances of the type from their PEM encoding. */
        fun list(pemEncoded: String): Iterable<AbstractType>
    }
}

open class Asn1DecodersImpl<Asn1Type : Any, AbstractType : WithSourceRepresentation> @SignumInternals constructor (
    private val convertingBuilder: (Asn1Type)->AbstractType,
    protected val serializer: KSerializer<Asn1Type>
) : Asn1Decoders<Asn1Type, AbstractType> {

    override operator fun invoke(asn1Representation: Asn1Type): AbstractType =
        convertingBuilder(asn1Representation)

    override operator fun invoke(asn1Element: Asn1Element): AbstractType =
        invoke(Signum.Der.decodeFromTlv(serializer, asn1Element))

    override operator fun invoke(derBytes: ByteArray): AbstractType =
        invoke(Signum.Der.decodeFromByteArray(serializer, derBytes))

    override operator fun invoke(derSource: Source, limit: Long): AbstractType =
        invoke(Signum.Der.decodeFromSource(serializer, derSource, limit))

    /** Parses the type from its hex-encoded DER encoding. */
    override fun fromHexString(derHexBytes: String): AbstractType =
        invoke(Signum.Der.decodeFromHexString(serializer, derHexBytes))

    class WithPEM<Asn1Type : WithPemLabel, AbstractType: WithSourceRepresentation> @SignumInternals constructor(
        convertingBuilder: (Asn1Type)->AbstractType,
        serializer: KSerializer<Asn1Type>,
        private val pemSpec: PemDeserializable<Asn1Type>
    ) :
        Asn1DecodersImpl<Asn1Type, AbstractType>(convertingBuilder, serializer),
        Asn1Decoders.WithPEM<Asn1Type, AbstractType>
    {
        override operator fun invoke(pemEncoded: String): AbstractType =
            invoke(pemSpec.decodeFromPem(serializer, pemEncoded, Signum.Der))

        override fun list(pemEncoded: String): Iterable<AbstractType> =
            pemSpec.decodeAllFromPem(serializer, pemEncoded, Signum.Der).map(::invoke)
    }
}

inline fun <reified Asn1Type: Any, reified AbstractType: WithSourceRepresentation> asn1Decoders(
    crossinline fn: (Asn1Type)->AbstractType
): Asn1Decoders<Asn1Type, AbstractType> =
    Asn1DecodersImpl(
        decodeFrom(fn),
        Signum.Der.serializersModule.serializer<Asn1Type>())

inline fun <reified Asn1Type: WithPemLabel, reified AbstractType: WithSourceRepresentation> asn1Decoders(
    companion: PemDeserializable<Asn1Type>,
    crossinline fn: (Asn1Type)->AbstractType
): Asn1Decoders.WithPEM<Asn1Type, AbstractType> =
    Asn1DecodersImpl.WithPEM(
        decodeFrom(fn),
        Signum.Der.serializersModule.serializer<Asn1Type>(),
        companion
    )


inline fun <
    reified OriginalAsn1Type : WithPemLabel,
    reified AlternateAsn1Type : WithPemLabel,
    reified AbstractType : WithSourceRepresentation
> Asn1Decoders.WithPEM<OriginalAsn1Type, AbstractType>.withAlternativePemDecoder(
    alternateDecoder: Asn1Decoders.WithPEM<AlternateAsn1Type, AbstractType>
) = object : Asn1Decoders.WithPEM<OriginalAsn1Type, AbstractType> by this {
    override fun invoke(pemEncoded: String): AbstractType {
        return try {
            alternateDecoder(pemEncoded)
        } catch (x: IllegalArgumentException) {
            if (x.message?.contains("Unexpected PEM label") == true) {
                this@withAlternativePemDecoder(pemEncoded)
            } else throw x
        }
    }
}

@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
/** Provider + no PEM + unknown doesn't want source */
inline fun <
    reified ProviderType: Any,
    reified Asn1Type: Any,
    reified AbstractType: WithSourceRepresentation,
    UnknownType
> asn1DecodersWith(
    crossinline fn: ProviderType.(Asn1Type)->AbstractType?,
    crossinline unknownCtor: (UnsupportedCryptoException)->UnknownType
) : Asn1Decoders<Asn1Type, AbstractType> where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim =
    Asn1DecodersImpl(
        decodeWith(fn, unknownCtor),
        Signum.Der.serializersModule.serializer<Asn1Type>(),
    )

@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
/** Provider + no PEM + unknown wants source */
inline fun <
    reified ProviderType: Any,
    reified Asn1Type: Any,
    reified AbstractType: WithSourceRepresentation,
    UnknownType
> asn1DecodersWith(
    crossinline fn: ProviderType.(Asn1Type)->AbstractType?,
    crossinline unknownCtor: (Asn1Type, UnsupportedCryptoException)->UnknownType
) : Asn1Decoders<Asn1Type, AbstractType> where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim =
    Asn1DecodersImpl(
        decodeWith(fn, unknownCtor),
        Signum.Der.serializersModule.serializer<Asn1Type>(),
    )

@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
/** Provider + PEM + unknown doesn't want source */
inline fun <
    reified ProviderType: Any,
    reified Asn1Type: WithPemLabel,
    reified AbstractType: WithSourceRepresentation,
    UnknownType
> asn1DecodersWith(
    companion: PemDeserializable<Asn1Type>,
    crossinline fn: ProviderType.(Asn1Type)->AbstractType?,
    crossinline unknownCtor: (UnsupportedCryptoException)->UnknownType
) : Asn1Decoders.WithPEM<Asn1Type, AbstractType> where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim =
    Asn1DecodersImpl.WithPEM(
        decodeWith(fn, unknownCtor),
        Signum.Der.serializersModule.serializer<Asn1Type>(),
        companion
    )

@Suppress("BOUNDS_NOT_ALLOWED_IF_BOUNDED_BY_TYPE_PARAMETER")
/** Provider + PEM + unknown wants source */
inline fun <
    reified ProviderType: Any,
    reified Asn1Type: WithPemLabel,
    reified AbstractType: WithSourceRepresentation,
    UnknownType
> asn1DecodersWith(
    companion: PemDeserializable<Asn1Type>,
    crossinline fn: ProviderType.(Asn1Type)->AbstractType?,
    crossinline unknownCtor: (Asn1Type, UnsupportedCryptoException)->UnknownType
) : Asn1Decoders.WithPEM<Asn1Type, AbstractType> where UnknownType : AbstractType, UnknownType : ServiceLoader.UnknownShim =
    Asn1DecodersImpl.WithPEM(
        decodeWith(fn, unknownCtor),
        Signum.Der.serializersModule.serializer<Asn1Type>(),
        companion
    )

}

//// ==========================================
//// GENERIC CODE DONE; actual extensions below
//// ==========================================

val SignatureAlgorithm.asn1 get() =
    asn1EncodersWith(Asn1SignatureAlgorithmProvider::encodeToAsn1)

val SignatureAlgorithm.Companion.fromAsn1 get() =
    asn1DecodersWith(Asn1SignatureAlgorithmProvider::decodeFromAsn1, SignatureAlgorithm::Unknown)

val Digest.asn1 get() =
    asn1EncodersWith(Asn1DigestAlgorithmProvider::encodeToAsn1)

val Digest.Companion.fromAsn1 get() =
    asn1DecodersWith(Asn1DigestAlgorithmProvider::decodeFromAsn1, Digest::Unknown)

val MessageAuthenticationCode.asn1 get() =
    asn1EncodersWith(Asn1MACAlgorithmProvider::encodeToAsn1)

val MessageAuthenticationCode.Companion.fromAsn1 get() =
    asn1DecodersWith(Asn1MACAlgorithmProvider::decodeFromAsn1, MessageAuthenticationCode::Unknown)

val CryptoPublicKey.asn1 get() =
    asn1EncodersWith(Asn1PublicKeyFormatProvider::encodeToAsn1)

val CryptoPublicKey.Companion.fromAsn1 get() =
    asn1DecodersWith(SubjectPublicKeyInfo.Companion, Asn1PublicKeyFormatProvider::decodeFromAsn1, CryptoPublicKey::Unknown)
        .withAlternativePemDecoder(RsaPublicKey.fromAsn1.PKCS1)

val KeyAgreementPublicValue.Companion.fromAsn1 get() =
    asn1Decoders<SubjectPublicKeyInfo,_> {
        CryptoPublicKey.fromAsn1(it) as KeyAgreementPublicValue
    }

val CryptoPrivateKey.asn1 get() =
    asn1EncodersWith(Asn1PrivateKeyFormatProvider::encodeToAsn1)

val CryptoPrivateKey.Companion.fromAsn1 get() =
    asn1DecodersWith(Pkcs8PrivateKeyInfo.Companion, Asn1PrivateKeyFormatProvider::decodeFromAsn1, CryptoPrivateKey::Unknown)
        .withAlternativePemDecoder(RsaPrivateKey.fromAsn1.PKCS1)
        .withAlternativePemDecoder(EcdsaPrivateKey.fromAsn1.SEC1)

private class X509UnparsedSignature : AbstractSignature {
    override val sourceRepresentation = SourceRepresentationStorage()
    override fun withSignatureAlgorithm(signatureAlgorithm: SignatureAlgorithm) =
        ServiceLoader.load<SignatureFormatProvider>().get(signatureAlgorithm) {
            parseCryptoSignature(it, this@X509UnparsedSignature.asn1.toRepresentation())
        }

    override fun toString() = "Unparsed CryptoSignature (from X.509: $sourceRepresentation)"
}

val AbstractSignature.Companion.fromAsn1 get() =
    asn1Decoders<X509SignatureValue, AbstractSignature> { X509UnparsedSignature() }

val AbstractSignature.asn1 get() =
    when (this) {
        is CryptoSignature -> this@asn1.asn1
        else -> asn1Encoders<X509SignatureValue, _> { throw UnsupportedOperationException("Unparsed signature in format ${this.sourceFormat} cannot be converted to ASN.1") }
    }

val CryptoSignature.Companion.fromAsn1 get() =
    AbstractSignature.fromAsn1

val CryptoSignature.asn1 get() =
    asn1EncodersWith(SignatureFormatProvider::encodeToAsn1)

val TbsCertificate.asn1 get() = asn1Encoders<X509TbsCertificate,_> {
    X509TbsCertificate(
        serialNumber = serialNumber.toAsn1Integer(),
        signatureAlgorithm = signatureAlgorithm.asn1.toRepresentation(),
        issuerName = issuerName.asn1.toRepresentation(),
        validFrom = Asn1Time.SecondsCapped(validFrom),
        validUntil = Asn1Time.SecondsCapped(validUntil),
        subjectName = subjectName.asn1.toRepresentation(),
        subjectPublicKeyInfo = publicKey.asn1.toRepresentation(),
        issuerUniqueID = issuerUniqueID?.let { Asn1BitString(it) },
        subjectUniqueID = subjectUniqueID?.let { Asn1BitString(it) },
        extensions = extensions.map { it.asn1.toRepresentation() }
    )
}

val TbsCertificate.Companion.fromAsn1 get() = asn1Decoders<X509TbsCertificate,_> { src ->
    TbsCertificate(
        serialNumber = src.serialNumber.toBigInteger(),
        signatureAlgorithm = SignatureAlgorithm.fromAsn1(src.signatureAlgorithm),
        issuerName = Name.fromAsn1(src.issuerName),
        validFrom = src.validity.validFrom.instant,
        validUntil = src.validity.validUntil.instant,
        subjectName = Name.fromAsn1(src.subjectName),
        publicKey = CryptoPublicKey.fromAsn1(src.subjectPublicKeyInfo),
        issuerUniqueID = src.issuerUniqueID?.bitCarryingBytes,
        subjectUniqueID = src.subjectUniqueID?.bitCarryingBytes,
        extensions = src.extensions?.map { CertificateExtension.fromAsn1(it) }.orEmpty(),
        strict = false, // Received serial numbers need not meet the constraints imposed on new certificates.
    )
}

val CertificateExtension.asn1 get() =
    asn1EncodersWith(CertificateExtensionProvider::encodeToAsn1)

val CertificateExtension.Companion.fromAsn1 get() =
    asn1DecodersWith(CertificateExtensionProvider::decodeFromAsn1) { asn1, lookup ->
        object : CertificateExtension.Unknown(lookup) {
            override val critical = asn1.critical
            override val oid: ObjectIdentifier = asn1.oid
        }
    }

val Certificate.asn1 get() =
    asn1Encoders<X509Certificate, _> { src ->
        X509Certificate(
            tbsCertificate = src.tbsCertificate.asn1.toRepresentation(),
            signatureAlgorithm = src.tbsCertificate.signatureAlgorithm.asn1.toRepresentation(),
            signatureValue = src.signatureValue.asn1.toRepresentation(),
        )
    }

val Certificate.Companion.fromAsn1 get() =
    asn1Decoders(X509Certificate.Companion) { src ->
        require(src.signatureAlgorithm == src.tbsCertificate.signatureAlgorithm) {
            "Inner TBS certificate signature algorithm ${src.tbsCertificate.signatureAlgorithm} != certificate outer " +
                    "signature algorithm ${src.signatureAlgorithm}, that earns the whole certificate with serial " +
                    "${src.tbsCertificate.serialNumber} a spot on my naughty list!"
        }
        Certificate(
            tbsCertificate = TbsCertificate.fromAsn1(src.tbsCertificate),
            signatureValue = CryptoSignature.fromAsn1(src.signatureValue))
    }

val GeneralName.asn1 get() =
    asn1EncodersWith(GeneralNameFormatProvider::encodeToAsn1)

val GeneralName.Companion.fromAsn1 get() =
    asn1DecodersWith(GeneralNameFormatProvider::decodeFromAsn1, GeneralName::Unknown)

// TODO: do we want this to be part of the interface, so implementations can override without being tied to asn1?
val GeneralName.tag get() = this@tag.asn1.toRepresentation().tag

val AlternativeNames.asn1 get() =
    asn1Encoders<X509GeneralNames,_> {
        X509GeneralNames(generalNames.map { it.asn1.toRepresentation() })
    }

val AlternativeNames.Companion.fromAsn1 get() =
    asn1Decoders<X509GeneralNames,_> { src ->
        AlternativeNames(src.entries.map { GeneralName.fromAsn1(it) })
    }

val RelativeDistinguishedName.asn1 get() =
    asn1Encoders<X500RelativeDistinguishedName, _> { src ->
        X500RelativeDistinguishedName(src.attrsAndValues.map {
            it.asn1.toRepresentation()
        }.toSet())
    }

val RelativeDistinguishedName.Companion.fromAsn1 get() =
    asn1Decoders<X500RelativeDistinguishedName, _> { src ->
        RelativeDistinguishedName(src.attrsAndValues.map {
            AttributeTypeAndValue.fromAsn1(it)
        }.toSet())
    }

val AttributeTypeAndValue.asn1 get() =
    asn1Encoders<X500AttributeTypeAndValue, _> { src ->
        X500AttributeTypeAndValue(src.oid, src.value)
    }

val AttributeTypeAndValue.Companion.fromAsn1 get() =
    asn1Decoders<X500AttributeTypeAndValue, _> { src ->
        AttributeTypeAndValue(src.oid, src.value)
    }

val Name.asn1 get() =
    asn1Encoders<X500Name, _> { src ->
        X500Name(src.relativeDistinguishedNames.map { it.asn1.toRepresentation() })
    }

val Name.Companion.fromAsn1 get() =
    asn1Decoders<X500Name, _> { src ->
        Name(src.map {
            RelativeDistinguishedName.fromAsn1(it)
        })
    }

val CsrAttribute.asn1 get() =
    asn1Encoders<Pkcs10CsrAttribute, _> { src ->
        Pkcs10CsrAttribute(src.oid, src.value)
    }

val CsrAttribute.Companion.fromAsn1 get() =
    asn1Decoders<Pkcs10CsrAttribute, _> { src ->
        CsrAttribute(src.oid, src.value)
    }

val TbsCertificationRequest.asn1 get() =
    asn1Encoders<Pkcs10CertificationRequestInfo, _> { src ->
        Pkcs10CertificationRequestInfo(
            subjectName = src.subjectName.asn1.toRepresentation(),
            publicKey = src.publicKey.asn1.toRepresentation(),
            attributes = src.attributes.map { it.asn1.toRepresentation() }.toSet(),
        )
    }

val TbsCertificationRequest.Companion.fromAsn1 get() =
    asn1Decoders<Pkcs10CertificationRequestInfo, _> { src ->
        TbsCertificationRequest(
            subjectName = Name.fromAsn1(src.subjectName),
            publicKey = CryptoPublicKey.fromAsn1(src.publicKey),
            attributes = src.attributes.map { CsrAttribute.fromAsn1(it) },
        )
    }

val CertificationRequest.asn1 get() =
    asn1Encoders<Pkcs10CertificationRequest, _> { src ->
        Pkcs10CertificationRequest(
            certificationRequestInfo = src.tbsCsr.asn1.toRepresentation(),
            signatureAlgorithm = src.signatureAlgorithm.asn1.toRepresentation(),
            signatureValue = src.signatureValue.asn1.toRepresentation(),
        )
    }

val CertificationRequest.Companion.fromAsn1 get() =
    asn1Decoders(Pkcs10CertificationRequest.Companion) { src ->
        CertificationRequest(
            tbsCsr = TbsCertificationRequest.fromAsn1(src.certificationRequestInfo),
            signatureAlgorithm = SignatureAlgorithm.fromAsn1(src.signatureAlgorithm),
            signatureValue = CryptoSignature.fromAsn1(src.signatureValue),
        )
    }
