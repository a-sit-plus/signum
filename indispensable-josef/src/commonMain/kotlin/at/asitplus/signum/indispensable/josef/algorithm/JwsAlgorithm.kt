@file:Suppress("SERIALIZER_TYPE_INCOMPATIBLE")

package at.asitplus.signum.indispensable.josef.algorithm

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.DataIntegrityAlgorithm
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.ec.ECCurve
import at.asitplus.signum.indispensable.EcdsaSignatureAlgorithm
import at.asitplus.signum.indispensable.HmacAlgorithm
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.Pkcs1RsaSignaturePadding
import at.asitplus.signum.indispensable.PssRsaSignaturePadding
import at.asitplus.signum.indispensable.RsaSignatureAlgorithm
import at.asitplus.signum.indispensable.RsaSignatureMappingFamily
import at.asitplus.signum.indispensable.signature.Signature as SignumSignature
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.SignatureMappingKey
import at.asitplus.signum.indispensable.SpecializedDataIntegrityAlgorithm
import at.asitplus.signum.indispensable.SpecializedMessageAuthenticationCode
import at.asitplus.signum.indispensable.SpecializedSignatureAlgorithm
import at.asitplus.signum.indispensable.WithDigest
import at.asitplus.signum.indispensable.signature.EcSignature
import at.asitplus.signum.indispensable.signature.RsaSignature
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Since we support only JWS algorithms (with one exception), this class is called what it's called.
 */
@Serializable(with = JwsAlgorithmSerializer::class)
open class JwsAlgorithm(override val identifier: String) : JsonWebAlgorithm {
    override fun toString(): String = identifier

    companion object : Enumeration<JwsAlgorithm> {
        private val registeredById = linkedMapOf<String, JwsAlgorithm>()

        override val entries: Collection<JwsAlgorithm>
            get() {
                Signature.entries
                MAC.entries
                return registeredById.values
            }

        fun <T : JwsAlgorithm> register(algorithm: T): T {
            registeredById.putIfAbsent(algorithm.identifier, algorithm)
            return algorithm
        }

        fun fromIdentifier(identifier: String): JwsAlgorithm? {
            Signature.entries
            MAC.entries
            return registeredById[identifier]
        }
    }

    @Serializable(with = JwsAlgorithmSerializer::class)
    open class Signature(
        identifier: String,
        override val algorithm: SignatureAlgorithm,
        private val rawSignatureDecoder: (ByteArray) -> SignumSignature.RawByteEncodable,
    ) : JwsAlgorithm(identifier), SpecializedSignatureAlgorithm {

        open val digest: Digest?
            get() = (algorithm as? WithDigest)?.digest

        open fun decodeRawSignature(bytes: ByteArray): SignumSignature.RawByteEncodable =
            rawSignatureDecoder(bytes)

        companion object : Enumeration<Signature> {
            private val builtIns = linkedMapOf<String, Signature>()

            override val entries: Collection<Signature>
                get() = builtIns.values

            fun <T : Signature> register(algorithm: T): T {
                builtIns.putIfAbsent(algorithm.identifier, algorithm)
                JwsAlgorithm.register(algorithm)
                return algorithm
            }

            val ES256 = register(
                Signature(
                    "ES256",
                    EcdsaSignatureAlgorithm(Digest.SHA256, null),
                ) { EcSignature.fromRawBytes(ECCurve.SECP_256_R_1, it) }
            )
            val ES384 = register(
                Signature(
                    "ES384",
                    EcdsaSignatureAlgorithm(Digest.SHA384, null),
                ) { EcSignature.fromRawBytes(ECCurve.SECP_384_R_1, it) }
            )
            val ES512 = register(
                Signature(
                    "ES512",
                    EcdsaSignatureAlgorithm(Digest.SHA512, null),
                ) { EcSignature.fromRawBytes(ECCurve.SECP_521_R_1, it) }
            )
            val PS256 = register(
                Signature("PS256", RsaSignatureAlgorithm(Digest.SHA256, PssRsaSignaturePadding)) { RsaSignature(it) }
            )
            val PS384 = register(
                Signature("PS384", RsaSignatureAlgorithm(Digest.SHA384, PssRsaSignaturePadding)) { RsaSignature(it) }
            )
            val PS512 = register(
                Signature("PS512", RsaSignatureAlgorithm(Digest.SHA512, PssRsaSignaturePadding)) { RsaSignature(it) }
            )
            val RS256 = register(
                Signature("RS256", RsaSignatureAlgorithm(Digest.SHA256, Pkcs1RsaSignaturePadding)) { RsaSignature(it) }
            )
            val RS384 = register(
                Signature("RS384", RsaSignatureAlgorithm(Digest.SHA384, Pkcs1RsaSignaturePadding)) { RsaSignature(it) }
            )
            val RS512 = register(
                Signature("RS512", RsaSignatureAlgorithm(Digest.SHA512, Pkcs1RsaSignaturePadding)) { RsaSignature(it) }
            )
            val NON_JWS_SHA1_WITH_RSA = register(
                Signature("RS1", RsaSignatureAlgorithm(Digest.SHA1, Pkcs1RsaSignaturePadding)) {
                    RsaSignature(it)
                }
            )
        }
    }

    @Serializable(with = JwsAlgorithmSerializer::class)
    open class MAC(
        identifier: String,
        override val algorithm: MessageAuthenticationCode,
    ) : JwsAlgorithm(identifier), SpecializedMessageAuthenticationCode {
        companion object : Enumeration<MAC> {
            private val builtIns = linkedMapOf<String, MAC>()

            override val entries: Collection<MAC>
                get() = builtIns.values

            fun <T : MAC> register(algorithm: T): T {
                builtIns.putIfAbsent(algorithm.identifier, algorithm)
                JwsAlgorithm.register(algorithm)
                return algorithm
            }

            val HS256 = register(MAC("HS256", HmacAlgorithm.byDigest(Digest.SHA256)))
            val HS384 = register(MAC("HS384", HmacAlgorithm.byDigest(Digest.SHA384)))
            val HS512 = register(MAC("HS512", HmacAlgorithm.byDigest(Digest.SHA512)))
            val UNOFFICIAL_HS1 = register(MAC("H1", HmacAlgorithm.byDigest(Digest.SHA1)))
        }
    }
}

private const val JWS_SIGNATURE_NAMESPACE = "jws.signature"
private const val JWS_MAC_NAMESPACE = "jws.mac"

private val joseBuiltInMappings = run {
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.ES256.algorithm, JwsAlgorithm.Signature.ES256)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.ES384.algorithm, JwsAlgorithm.Signature.ES384)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.ES512.algorithm, JwsAlgorithm.Signature.ES512)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.RS256.algorithm, JwsAlgorithm.Signature.RS256)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.RS384.algorithm, JwsAlgorithm.Signature.RS384)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.RS512.algorithm, JwsAlgorithm.Signature.RS512)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.PS256.algorithm, JwsAlgorithm.Signature.PS256)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.PS384.algorithm, JwsAlgorithm.Signature.PS384)
    AlgorithmRegistry.registerSignatureMapping(JWS_SIGNATURE_NAMESPACE, JwsAlgorithm.Signature.PS512.algorithm, JwsAlgorithm.Signature.PS512)
    AlgorithmRegistry.registerSignatureMapping(
        JWS_SIGNATURE_NAMESPACE,
        SignatureMappingKey(RsaSignatureMappingFamily, Digest.SHA1, null, Pkcs1RsaSignaturePadding),
        JwsAlgorithm.Signature.NON_JWS_SHA1_WITH_RSA
    )
    AlgorithmRegistry.registerMacMapping(JWS_MAC_NAMESPACE, JwsAlgorithm.MAC.UNOFFICIAL_HS1.algorithm, JwsAlgorithm.MAC.UNOFFICIAL_HS1)
    AlgorithmRegistry.registerMacMapping(JWS_MAC_NAMESPACE, JwsAlgorithm.MAC.HS256.algorithm, JwsAlgorithm.MAC.HS256)
    AlgorithmRegistry.registerMacMapping(JWS_MAC_NAMESPACE, JwsAlgorithm.MAC.HS384.algorithm, JwsAlgorithm.MAC.HS384)
    AlgorithmRegistry.registerMacMapping(JWS_MAC_NAMESPACE, JwsAlgorithm.MAC.HS512.algorithm, JwsAlgorithm.MAC.HS512)
}

object JwsAlgorithmSerializer : KSerializer<JwsAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsAlgorithm) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JwsAlgorithm {
        val decoded = decoder.decodeString()
        return JwsAlgorithm.fromIdentifier(decoded)
            ?: throw IllegalArgumentException("Unknown JWS algorithm: $decoded")
    }
}

/** Tries to find a matching JWS algorithm. Note that JWS imposes curve restrictions on ECDSA based on the digest. */
fun SignatureAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    joseBuiltInMappings
    AlgorithmRegistry.findSignatureMapping<JwsAlgorithm.Signature>(JWS_SIGNATURE_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("$this has no JWS equivalent")
}

fun DataIntegrityAlgorithm.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    when (this) {
        is SignatureAlgorithm -> toJwsAlgorithm().getOrThrow()
        is MessageAuthenticationCode -> toJwsAlgorithm().getOrThrow()
        else -> throw UnsupportedCryptoException("$this has no JWS equivalent")
    }
}

fun MessageAuthenticationCode.toJwsAlgorithm(): KmmResult<JwsAlgorithm> = catching {
    joseBuiltInMappings
    AlgorithmRegistry.findMacMapping<JwsAlgorithm.MAC>(JWS_MAC_NAMESPACE, this)
        ?: throw UnsupportedCryptoException("$this has no JWS equivalent")
}

/** Tries to find a matching JWS algorithm*/
fun SpecializedDataIntegrityAlgorithm.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()

/** Tries to find a matching JWS algorithm.*/
fun SpecializedMessageAuthenticationCode.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()

/** Tries to find a matching JWS algorithm.*/
fun SpecializedSignatureAlgorithm.toJwsAlgorithm() =
    this.algorithm.toJwsAlgorithm()
