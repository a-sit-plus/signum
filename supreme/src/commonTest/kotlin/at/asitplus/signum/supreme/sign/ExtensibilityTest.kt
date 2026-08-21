package at.asitplus.signum.supreme.sign

import at.asitplus.awesn1.Asn1BitString
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Integer
import at.asitplus.awesn1.Asn1OctetString
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.Pkcs8PrivateKeyInfo
import at.asitplus.awesn1.crypto.SubjectPublicKeyInfo
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.crypto.X509SignatureValue
import at.asitplus.catching
import at.asitplus.io.UVarInt
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.dsl.EphemeralSignerConfiguration
import at.asitplus.signum.dsl.InMemorySignerConfiguration
import at.asitplus.signum.dsl.VerifierConfiguration
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoSignature
import at.asitplus.signum.indispensable.PrivateKeyFormatProvider
import at.asitplus.signum.indispensable.PublicKeyFormatProvider
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.SignatureFormatProvider
import at.asitplus.signum.indispensable.decodeFromDer
import at.asitplus.signum.indispensable.encodeToDer
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithm
import at.asitplus.signum.indispensable.integrity.SignatureAlgorithmsProvider
import at.asitplus.signum.indispensable.integrity.SignatureInput
import at.asitplus.signum.indispensable.integrity.SignatureVerifier
import at.asitplus.signum.indispensable.integrity.SignatureVerifierProvider
import at.asitplus.signum.indispensable.integrity.verifierFor
import at.asitplus.signum.indispensable.integrity.verify
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.signum.supreme.signCatching
import at.asitplus.signum.supreme.signature
import at.asitplus.signum.supreme.succeed
import at.asitplus.signum.supreme.verify
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.should
import io.kotest.matchers.shouldBe
import org.kotlincrypto.random.CryptoRand
import kotlin.random.Random
import kotlin.time.Clock
import kotlin.time.Duration.Companion.minutes
import kotlin.uuid.Uuid

private val Byte.hasHighest get() = (this.countLeadingZeroBits() == 0)
private val ByteArray.hasHighest get() = get(0).hasHighest
private fun byteArrayOfHighest(bit: Boolean) = ByteArray(if (bit) 0x80 else 0x00)


/**
 * We implement our own custom signature scheme! We call it the "cursory signature scheme", because it looks
 * no further than the first bit of the input, and the first bit of the private key (which is only one bit!)
 * XOR them together. Very signature, very secure! Wow!
 */
object CursorySignatureScheme : SignatureAlgorithm {
    val OID = ObjectIdentifier(Uuid.parse("01a00ebe-aa38-733c-ad7e-42442b6a8a35"))
    val ALG = X509AlgorithmIdentifier(OID, null)
    override val asn1Representation get() = ALG
    data class Signature(private val bit: Boolean) : CryptoSignature.RawByteEncodable {
        override val asn1Representation: X509SignatureValue
            get() = X509SignatureValue(Asn1BitString(bit))
        override val rawByteArray: ByteArray
            get() = byteArrayOfHighest(bit)
    }
    data class Key(private val bit: Boolean) : CryptoPublicKey(), Signer.WithExportableKey, SignatureVerifier {
        companion object {
            val OID = ObjectIdentifier(Uuid.parse("01a00ed6-7067-7149-a548-40aa87ed4bbc"))
        }
        override val oid: ObjectIdentifier get() = OID
        override val didCodec: UVarInt get() = error("")
        override val didKeyBytes: ByteArray get() = error("")
        override val asn1Representation: SubjectPublicKeyInfo get() =
            SubjectPublicKeyInfo(
                ALG,
                Asn1BitString(bit))

        inner class Private : CryptoPrivateKey.WithPublicKey {
            override val attributes = setOf<Asn1Element>()
            override val publicKey = this@Key
            override val asn1Representation = Pkcs8PrivateKeyInfo(
                Pkcs8PrivateKeyInfo.Version.V1,
                ALG,
                Asn1OctetString(byteArrayOfHighest(bit))
            )
            override val oid: ObjectIdentifier get() = OID
        }

        @SecretExposure
        override suspend fun exportPrivateKey() = TODO()
        override val publicKey: CryptoPublicKey get() = this

        override val signatureAlgorithm: SignatureAlgorithm get() = CursorySignatureScheme
        override suspend fun sign(data: SignatureInput) = signCatching {
            require(data.format == null)
            val dataHasHighest = data.data.first(ByteArray::isNotEmpty).hasHighest
            Signature(dataHasHighest != this.bit)
        }

        override suspend fun verify(data: SignatureInput, sig: CryptoSignature) = catching {
            require(sig is CursorySignatureScheme.Signature)
            require(sign(data).signature == sig) { "Invalid signature" }
            SignatureVerifier.Success
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
    override fun getAlgorithm(algorithmIdentifier: X509AlgorithmIdentifier) =
        CursorySignatureScheme.takeIf { algorithmIdentifier == CursorySignatureScheme.ALG }
    override fun getAlgorithms() = listOf(CursorySignatureScheme)
    override suspend fun makeEphemeralSigner(configuration: EphemeralSignerConfiguration): CursorySignatureScheme.Key? {
        val v = configuration.cursory.v ?: return null
        return CursorySignatureScheme.Key(
            v.overrideKey ?: CryptoRand.nextBytes(ByteArray(1)).hasHighest)
    }

    override fun createSignerForKey(
        algorithm: SignatureAlgorithm,
        privateKey: CryptoPrivateKey.WithPublicKey,
        configuration: InMemorySignerConfiguration
    ): Signer.WithExportableKey? {
        if (algorithm != CursorySignatureScheme) return null
        require (privateKey is CursorySignatureScheme.Key.Private)
        return privateKey.publicKey
    }

    override fun decodeFromAsn1(publicKeyInfo: SubjectPublicKeyInfo): CryptoPublicKey? {
        return if (publicKeyInfo.algorithmIdentifier == CursorySignatureScheme.ALG) {
            publicKeyInfo.subjectPublicKey
                .also { require(it.sizeBits == 1L) }
                .get(0)
                .let(CursorySignatureScheme::Key)
        } else null
    }

    override fun decodeFromAsn1(privateKeyInfo: Pkcs8PrivateKeyInfo): CryptoPrivateKey? {
        if (privateKeyInfo.version != Pkcs8PrivateKeyInfo.Version.V1) return null
        if (privateKeyInfo.privateKeyAlgorithm != CursorySignatureScheme.ALG) return null
        return CursorySignatureScheme.Key(privateKeyInfo.privateKey.content.hasHighest).Private()
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
                .also { require(it.sizeBits == 1L) }
                .let { CursorySignatureScheme.Signature(it[0]) }
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
    ServiceLoader.register<SignatureAlgorithmsProvider>(CursorySignatureSchemeProvider)
    ServiceLoader.register<InMemoryKeysProvider>(CursorySignatureSchemeProvider)
    ServiceLoader.register<PublicKeyFormatProvider>(CursorySignatureSchemeProvider)
    ServiceLoader.register<PrivateKeyFormatProvider>(CursorySignatureSchemeProvider)
    ServiceLoader.register<SignatureVerifierProvider>(CursorySignatureSchemeProvider)
    ServiceLoader.register<SignatureFormatProvider>(CursorySignatureSchemeProvider)
    "Signing" {
        repeat (50) {
            val privateKey = Signer.Ephemeral { cursory {} }
            val publicKey = privateKey.publicKey
            val data = Random.nextBytes(1)
            val signature = privateKey.sign(data).signature
            CursorySignatureScheme.verifierFor(publicKey).verify(data, signature) should succeed
        }
    }

    "Certificates" {
        repeat(50) {
            val data = Random.nextBytes(1)
            val privateKey = Signer.Ephemeral { cursory {} }
            val theSignature = privateKey.sign(data).signature.encodeToDer()
            val theCertificate = run {
                val publicKey = privateKey.publicKey
                val tbsCertificate = TbsCertificate(
                    serialNumber = Asn1Integer.ONE,
                    validFrom = Clock.System.now(),
                    validUntil = Clock.System.now() + 60.minutes,
                    signatureAlgorithm = CursorySignatureScheme,
                    publicKey = publicKey,
                    issuerName = X500Name.fromString("2.5.4.3=Test,2.5.4.6=AT"),
                    subjectName = X500Name.EMPTY
                )
                val signature = privateKey.sign(tbsCertificate.encodeToDer()).signature
                Certificate(tbsCertificate, signature).encodeToDer()
            }

            val parsedCertificate = Certificate.decodeFromDer(theCertificate)
            parsedCertificate.publicKey shouldBe privateKey.publicKey
            val verifier = CursorySignatureScheme.verifierFor(parsedCertificate.publicKey)
            verifier.verify(parsedCertificate) should succeed
            val parsedSignature = CryptoSignature.decodeFromDer(theSignature)
            verifier.verify(data, parsedSignature) should succeed
        }
    }
}
