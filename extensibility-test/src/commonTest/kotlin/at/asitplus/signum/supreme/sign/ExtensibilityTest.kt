package at.asitplus.signum.supreme.sign
import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.decodeFromTlv
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.decodeFromByteArray

import at.asitplus.awesn1.*
import at.asitplus.signum.Signum
import at.asitplus.signum.indispensable.pki.X509
import kotlinx.serialization.SerializationException
import kotlinx.serialization.modules.SerializersModule
import io.kotest.matchers.types.shouldBeSameInstanceAs
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.io.UVarInt
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.*
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.value
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificationRequest
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

private val Byte.hasHighest get() = (this.countLeadingZeroBits() == 0)
private val ByteArray.hasHighest get() = get(0).hasHighest
private fun byteArrayOfHighest(bit: Boolean) = byteArrayOf(if (bit) 0x80.toByte() else 0x00)

/**
 * We implement our own custom signature scheme! We call it the "cursory signature scheme", because it looks
 * no further than the first bit of the input, and the first bit of the private key (which is only one bit!)
 * XOR them together. Very signature, very secure! Wow!
 */
object CursorySignatureScheme : SignatureAlgorithm {
    val OID = ObjectIdentifier(Uuid.parse("01a00ebe-aa38-733c-ad7e-42442b6a8a35"))
    val ALG = X509AlgorithmIdentifier(OID, null)
    data class Signature(val bit: Boolean, override val sourceRepresentation: Pair<Encodable.Representation, Any>? = null) : CryptoSignature {
        override fun equals(other: Any?) = other is Signature && bit == other.bit
        override fun hashCode() = bit.hashCode()
    }
    data class Key(val bit: Boolean, override val sourceRepresentation: Pair<Encodable.Representation, Any>? = null) : CryptoPublicKey, Signer.WithExportableKey, SignatureVerifier {
        override fun equals(other: Any?) = other is Key && bit == other.bit
        override fun hashCode() = bit.hashCode()
        companion object {
            val OID = ObjectIdentifier(Uuid.parse("01a00ed6-7067-7149-a548-40aa87ed4bbc"))
            val ALG = X509AlgorithmIdentifier(OID, null)
        }

        override val additionalProperties = mutableMapOf<String, String>()
        override val didCodec: UVarInt get() = error("")
        override val didKeyBytes: ByteArray get() = error("")
        inner class Private(override val sourceRepresentation: Pair<Encodable.Representation, Any>? = null) : CryptoPrivateKey.WithPublicKey {
            override val publicKey = this@Key
            override val attributes: Set<Asn1Element>? = null
            override fun equals(other: Any?) = other is Private && publicKey == other.publicKey
            override fun hashCode() = publicKey.hashCode()
        }

        @SecretExposure
        override suspend fun exportPrivateKey() = TODO()
        override val publicKey: CryptoPublicKey get() = this

        override val signatureAlgorithm: SignatureAlgorithm get() = CursorySignatureScheme
        override suspend fun sign(data: SignatureInput) = SignatureResult.make {
            require(data.format == null)
            val dataHasHighest = data.data.first(ByteArray::isNotEmpty).hasHighest
            Signature(dataHasHighest != this.bit)
        }

        override suspend fun verify(data: SignatureInput, sig: CryptoSignature): SignatureVerifier.Success {
            require(sig is CursorySignatureScheme.Signature)
            require(sign(data).signature == sig) { "Invalid signature" }
            return SignatureVerifier.Success
        }

        class Config : EphemeralSignerConfiguration.AlgorithmSpecific() {
            var overrideKey: Boolean? = null
        }
    }
}
val EphemeralSignerConfiguration.cursory get() =
    _algSpecific.option("CURSORY", CursorySignatureScheme.Key::Config)

object CursorySignatureSchemeProvider :
    SignatureAlgorithmsProvider, InMemoryKeysProvider, PublicKeyFormatProvider, PrivateKeyFormatProvider,
        SignatureVerifierProvider, SignatureFormatProvider
{
    val asn1Serializers = SerializersModule {
        contextualAsn1(CursorySignatureScheme::class, X509AlgorithmIdentifier.serializer(),
            { it.asn1Representation },
            { requireNotNull(getAlgorithm(it)) })
        contextualAsn1(CursorySignatureScheme.Key::class, SubjectPublicKeyInfo.serializer(),
            { it.asn1Representation },
            { requireNotNull(decodeFromAsn1(it)) as CursorySignatureScheme.Key })
        contextualAsn1(CursorySignatureScheme.Key.Private::class, Pkcs8PrivateKeyInfo.serializer(),
            { it.asn1Representation },
            { requireNotNull(decodeFromAsn1(it)) as CursorySignatureScheme.Key.Private })
        contextualAsn1(CursorySignatureScheme.Signature::class, X509SignatureValue.serializer(),
            { it.asn1Representation },
            { requireNotNull(parseCryptoSignature(CursorySignatureScheme, it)) as CursorySignatureScheme.Signature })
    }

    fun install() {
        Signum.register(this, asn1Serializers)
    }

    override fun encodeToAsn1(value: SignatureAlgorithm): X509AlgorithmIdentifier? =
        CursorySignatureScheme.ALG.takeIf { value == CursorySignatureScheme }

    override fun encodeToAsn1(value: CryptoPublicKey): SubjectPublicKeyInfo? =
        (value as? CursorySignatureScheme.Key)?.let {
            SubjectPublicKeyInfo(CursorySignatureScheme.Key.ALG, Asn1BitString(it.bit))
        }

    override fun encodeToAsn1(value: CryptoPrivateKey): Pkcs8PrivateKeyInfo? =
        (value as? CursorySignatureScheme.Key.Private)?.let {
            Pkcs8PrivateKeyInfo(CursorySignatureScheme.Key.ALG, Asn1OctetString(byteArrayOfHighest(it.publicKey.bit)))
        }

    override fun encodeToAsn1(value: CryptoSignature): X509SignatureValue? =
        (value as? CursorySignatureScheme.Signature)?.let { X509SignatureValue(Asn1BitString(it.bit)) }

    override fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier) =
        CursorySignatureScheme.takeIf { algorithmIdentifier == CursorySignatureScheme.ALG }
    override suspend fun makeEphemeralSigner(config: EphemeralSignerConfiguration): CursorySignatureScheme.Key? {
        val v = config.cursory.v ?: return null
        return CursorySignatureScheme.Key(
            v.overrideKey ?: CryptoRand.nextBytes(ByteArray(1)).hasHighest)
    }

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey,
        config: InMemorySignerConfiguration
    ): Signer.WithExportableKey? {
        if (algorithm != CursorySignatureScheme) return null
        require (privateKey is CursorySignatureScheme.Key.Private)
        return privateKey.publicKey
    }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey? {
        return if (publicKeyInfo.algorithmIdentifier == CursorySignatureScheme.Key.ALG) {
            publicKeyInfo.subjectPublicKey
                .also { require(it.logicalBitCount == 1L) }
                .get(0)
                .let { CursorySignatureScheme.Key(it, X509 to publicKeyInfo) }
        } else null
    }

    override fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo): CryptoPrivateKey? {
        if (privateKeyInfo.version != Pkcs8PrivateKeyInfo.Version.V1) return null
        if (privateKeyInfo.privateKeyAlgorithm != CursorySignatureScheme.Key.ALG) return null
        return CursorySignatureScheme.Key(privateKeyInfo.privateKey.content.hasHighest).Private(X509 to privateKeyInfo)
    }

    override fun decodeFromDidKey(codec: UVarInt, keyBytes: ByteArray) = null

    override fun verifierFor(algorithm: SignatureAlgorithm, key: CryptoPublicKey, config: VerifierConfiguration): SignatureVerifier? {
        return if (algorithm == CursorySignatureScheme) (key as CursorySignatureScheme.Key) else null
    }

    override fun parseCryptoSignature(
        signatureAlgorithm: SignatureAlgorithm,
        signature: X509SignatureValue
    ): CryptoSignature? {
        if (signatureAlgorithm != CursorySignatureScheme) return null
        return signature.rawBitString
                .also { require(it.logicalBitCount == 1L) }
                .let { CursorySignatureScheme.Signature(it[0], X509 to signature) }
    }

    override fun parseCryptoSignature(
        x509Algorithm: X509AlgorithmIdentifier,
        signature: X509SignatureValue
    ): CryptoSignature? {
        if (x509Algorithm != CursorySignatureScheme.ALG) return null
        return parseCryptoSignature(CursorySignatureScheme, signature)
    }
}

val ExtensibilityTest by matrixSuite {
    "Rejected combined registration leaves provider priority unchanged" {
        val before = Signum.load<SignatureAlgorithmsProvider>().toList()
        shouldThrow<IllegalStateException> {
            Signum.register(CursorySignatureSchemeProvider, CursorySignatureSchemeProvider.asn1Serializers)
        }
        Signum.load<SignatureAlgorithmsProvider>().toList() shouldBe before
    }

    "Concrete contextual serializers on a custom DER instance" {
        val der = DER {
            serializersModule = SerializersModule {
                include(signumAsn1Serializers)
                include(CursorySignatureSchemeProvider.asn1Serializers)
            }
        }
        val key = CursorySignatureScheme.Key(true)
        key.sourceRepresentation shouldBe null
        val baseOnlyDer = DER { serializersModule = signumAsn1Serializers }
        shouldThrow<SerializationException> { baseOnlyDer.encodeToByteArray(key) }
        val baseKey: CryptoPublicKey = key
        baseOnlyDer.decodeFromByteArray<CryptoPublicKey>(baseOnlyDer.encodeToByteArray(baseKey)) shouldBe key
        val parsedKey = der.decodeFromByteArray<CursorySignatureScheme.Key>(der.encodeToByteArray(key))
        parsedKey shouldBe key
        parsedKey.hashCode() shouldBe key.hashCode()
        parsedKey.asn1Representation shouldBeSameInstanceAs parsedKey.sourceRepresentationFor(X509)
        (parsedKey.sourceRepresentationFor(X509) as SubjectPublicKeyInfo) shouldBe key.asn1Representation
        der.encodeToByteArray(parsedKey).contentEquals(der.encodeToByteArray(key)) shouldBe true

        val privateKey = key.Private()
        privateKey.sourceRepresentation shouldBe null
        val parsedPrivateKey = der.decodeFromByteArray<CursorySignatureScheme.Key.Private>(der.encodeToByteArray(privateKey))
        parsedPrivateKey shouldBe privateKey
        parsedPrivateKey.asn1Representation shouldBeSameInstanceAs parsedPrivateKey.sourceRepresentationFor(X509)
        parsedPrivateKey.sourceRepresentationFor(X509) shouldBe privateKey.asn1Representation
        der.encodeToByteArray(parsedPrivateKey).contentEquals(der.encodeToByteArray(privateKey)) shouldBe true

        der.decodeFromByteArray<CursorySignatureScheme>(der.encodeToByteArray(CursorySignatureScheme)) shouldBe CursorySignatureScheme
        val signature = CursorySignatureScheme.Signature(true)
        val parsedSignature = der.decodeFromByteArray<CursorySignatureScheme.Signature>(der.encodeToByteArray(signature))
        parsedSignature shouldBe signature
        parsedSignature.hashCode() shouldBe signature.hashCode()
        (parsedSignature.sourceRepresentationFor(X509) as X509SignatureValue).rawBitString shouldBe signature.asn1Representation.rawBitString
        der.encodeToByteArray(parsedSignature).contentEquals(der.encodeToByteArray(signature)) shouldBe true
    }

    "Public signing and verification helpers use Signum.Der" {
        val key = CursorySignatureScheme.Key(true)
        val tbs = TbsCertificate(
            serialNumber = Asn1Integer.ONE,
            validFrom = Clock.System.now(),
            validUntil = Clock.System.now() + 60.minutes,
            signatureAlgorithm = CursorySignatureScheme,
            publicKey = key,
            issuerName = X500Name.EMPTY,
            subjectName = X500Name.EMPTY,
        )
        val cert = key.sign(tbs)
        key.verify(cert) shouldBe SignatureVerifier.Success
        val signature = key.sign<TbsCertificate>(tbs).signature
        key.verify<TbsCertificate>(tbs, signature) shouldBe SignatureVerifier.Success
        key.verify(tbs, signature) shouldBe SignatureVerifier.Success

        val csr = key.sign(TbsCertificationRequest(X500Name.EMPTY, key, attributes = emptyList()))
        key.verify(csr) shouldBe SignatureVerifier.Success
        csr.verify() shouldBe SignatureVerifier.Success
    }

    "X.509 resolution" {
        val algorithm: SignatureAlgorithm = CursorySignatureScheme
        Signum.Der.decodeFromByteArray<SignatureAlgorithm>(Signum.Der.encodeToByteArray(algorithm)) shouldBe algorithm
        val key: CryptoPublicKey = CursorySignatureScheme.Key(true)
        Signum.Der.decodeFromByteArray<CryptoPublicKey>(Signum.Der.encodeToByteArray(key)) shouldBe key
        SignatureAlgorithm.fromAsn1Representation(CursorySignatureScheme.ALG) shouldBe CursorySignatureScheme
        shouldThrow<UnsupportedCryptoException> { SignatureAlgorithm.fromAsn1Representation(CursorySignatureScheme.Key.ALG) }

        val keyWithAlgOid = CursorySignatureScheme.Key(true).asn1Representation.copy(algorithmIdentifier = CursorySignatureScheme.ALG)
        shouldThrow<UnsupportedCryptoException> { CryptoPublicKey.fromAsn1Representation(keyWithAlgOid) }
    }

    "Signing" {
        repeat (50) {
            val privateKey = Signer.Ephemeral { cursory {} }
            val publicKey = privateKey.publicKey
            val data = Random.nextBytes(1)
            val signature = privateKey.sign(data).signature
            shouldNotThrowAny { CursorySignatureScheme.verifierFor(publicKey).verify(data, signature) }
        }
    }

    "Certificates" {
        repeat(50) {
            val data = Random.nextBytes(1)
            val privateKey = Signer.Ephemeral { cursory {} }
            val theSignature = Signum.Der.encodeToByteArray(privateKey.sign(data).signature)
            val theCertificate = run {
                val publicKey = privateKey.publicKey
                val certificateName = X500Name.fromString("name=JohnDoe,Title=Dr,C=Austria")
                val tbsCertificate = TbsCertificate(
                    serialNumber = Asn1Integer.ONE,
                    validFrom = Clock.System.now(),
                    validUntil = Clock.System.now() + 60.minutes,
                    signatureAlgorithm = CursorySignatureScheme,
                    publicKey = publicKey,
                    issuerName = certificateName,
                    subjectName = certificateName,
                )
                val signature = privateKey.sign(Signum.Der.encodeToByteArray(tbsCertificate)).signature
                Signum.Der.encodeToByteArray(Certificate(tbsCertificate, signature))
            }

            val parsedCertificate = Signum.Der.decodeFromByteArray<Certificate>(theCertificate)
            parsedCertificate.publicKey shouldBe privateKey.publicKey
            val nameAttributes = (parsedCertificate.tbsCertificate.subjectName as X500Name)
                .relativeDistinguishedNames
                .flatMap { it.attrsAndValues }
                .associateBy { it.oid }
            fun encodedValue(oid: String) =
                (nameAttributes.getValue(ObjectIdentifier(oid)) as AttributeTypeAndValue)
                    .value.asPrimitive()
            fun stringValue(oid: String) = Asn1String.decodeFromTlv(encodedValue(oid)).value
            encodedValue("2.5.4.41").tag shouldBe Asn1Element.Tag.STRING_UTF8
            encodedValue("2.5.4.12").tag shouldBe Asn1Element.Tag.STRING_UTF8
            encodedValue("2.5.4.6").tag shouldBe Asn1Element.Tag.STRING_PRINTABLE
            stringValue("2.5.4.41") shouldBe "JohnDoe"
            stringValue("2.5.4.12") shouldBe "Dr"
            stringValue("2.5.4.6") shouldBe "Austria"
            val verifier = CursorySignatureScheme.verifierFor(parsedCertificate.publicKey)
            verifier.verify(parsedCertificate) shouldBe SignatureVerifier.Success
            val parsedSignature = Signum.Der.decodeFromByteArray<SignatureValue>(theSignature)
            verifier.verify(data, parsedSignature) shouldBe SignatureVerifier.Success
        }
    }
}
