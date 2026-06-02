package at.asitplus.signum.indispensable.josef

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.symmetric.SpecializedSymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Suppress("SERIALIZER_TYPE_INCOMPATIBLE")
@Serializable(with = JweAlgorithmSerializer::class)
sealed class JweAlgorithm(override val identifier: String) : JsonWebAlgorithm, Enumerable {

    /**
     * ECDH-ES as per [RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037#section-3.2)
     */
    @Serializable(with = JweAlgorithmSerializer::class)
    object ECDH_ES : JweAlgorithm("ECDH-ES")

    sealed class HPKE(
        identifier: String, val kem_id: Int, val kdf_id: Int, val aead_id: Int)
        : JweAlgorithm(identifier), Enumerable
    {
        companion object : Enumeration<HPKE> {
            override val entries: Iterable<HPKE> by lazy {
                listOf(HPKE_0, HPKE_1, HPKE_2, HPKE_3, HPKE_4, HPKE_5, HPKE_6, HPKE_7)
            }
        }
    }
    sealed class HPKE_KE(
        identifier: String, val kem_id: Int, val kdf_id: Int, val aead_id: Int)
        : JweAlgorithm(identifier), Enumerable
    {
        companion object : Enumeration<HPKE_KE> {
            override val entries: Iterable<HPKE_KE> by lazy {
                listOf(HPKE_0_KE, HPKE_1_KE, HPKE_2_KE, HPKE_3_KE, HPKE_4_KE, HPKE_5_KE, HPKE_6_KE, HPKE_7_KE)
            }
        }
    }

    /** Integrated Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF and AES-128-GCM AEAD */
    data object HPKE_0 : HPKE("HPKE-0", 0x10, 0x1, 0x1)

    /** Integrated Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD */
    data object HPKE_1 : HPKE("HPKE-1", 0x11, 0x2, 0x2)

    /** Integrated Encryption with HPKE using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_2 : HPKE("HPKE-2", 0x12, 0x3, 0x2)

    /** Integrated Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_3 : HPKE("HPKE-3", 0x20, 0x1, 0x1)

    /** Integrated Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_4 : HPKE("HPKE-4", 0x20, 0x1, 0x3)

    /** Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_5 : HPKE("HPKE-5", 0x21, 0x3, 0x2)

    /** Integrated Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_6 : HPKE("HPKE-6", 0x21, 0x3, 0x3)

    /** Integrated Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD */
    data object HPKE_7 : HPKE("HPKE-7", 0x10, 0x1, 0x2)

    /** Key Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF and AES-128-GCM AEAD */
    data object HPKE_0_KE : HPKE_KE("HPKE-0-KE", 0x10, 0x1, 0x1)

    /** Key Encryption with HPKE using DHKEM(P-384, HKDF-SHA384) KEM, HKDF-SHA384 KDF, and AES-256-GCM AEAD */
    data object HPKE_1_KE : HPKE_KE("HPKE-1-KE", 0x11, 0x2, 0x2)

    /** Key Encryption with HPKE using DHKEM(P-521, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_2_KE : HPKE_KE("HPKE-2-KE" ,0x12, 0x3, 0x2)

    /** Key Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-128-GCM AEAD */
    data object HPKE_3_KE : HPKE_KE("HPKE-3-KE", 0x20, 0x1, 0x1)

    /** Key Encryption with HPKE using DHKEM(X25519, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_4_KE : HPKE_KE("HPKE-4-KE", 0x20, 0x1, 0x3)

    /** Key Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and AES-256-GCM AEAD */
    data object HPKE_5_KE : HPKE_KE("HPKE-5-KE", 0x21, 0x3, 0x2)

    /** Key Encryption with HPKE using DHKEM(X448, HKDF-SHA512) KEM, HKDF-SHA512 KDF, and ChaCha20Poly1305 AEAD */
    data object HPKE_6_KE : HPKE_KE("HPKE-6-KE", 0x21, 0x3, 0x3)

    /** Key Encryption with HPKE using DHKEM(P-256, HKDF-SHA256) KEM, HKDF-SHA256 KDF, and AES-256-GCM AEAD */
    data object HPKE_7_KE : HPKE_KE("HPKE-7-KE", 0x10, 0x1, 0x2)

    sealed class Symmetric(identifier: String, override val algorithm: SymmetricEncryptionAlgorithm<*,*,*>)
        : JweAlgorithm(identifier), SpecializedSymmetricEncryptionAlgorithm {

        companion object : Enumeration<Symmetric> {
            override val entries: Set<Symmetric> by lazy {
                setOf(A128KW, A192KW, A256KW, A128GCMKW, A192GCMKW, A256GCMKW)
            }
        }
    }

    @Serializable(with = JweAlgorithmSerializer::class)
    object A128KW : JweAlgorithm.Symmetric("A128KW", SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A192KW : JweAlgorithm.Symmetric("A192KW", SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A256KW : JweAlgorithm.Symmetric("A256KW", SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A128GCMKW : JweAlgorithm.Symmetric("A128GCMKW", SymmetricEncryptionAlgorithm.AES_128.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A192GCMKW : JweAlgorithm.Symmetric("A192GCMKW", SymmetricEncryptionAlgorithm.AES_192.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object A256GCMKW : JweAlgorithm.Symmetric("A256GCMKW", SymmetricEncryptionAlgorithm.AES_256.GCM)

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_256 : JweAlgorithm("RSA-OAEP-256")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_384 : JweAlgorithm("RSA-OAEP-384")

    @Serializable(with = JweAlgorithmSerializer::class)
    object RSA_OAEP_512 : JweAlgorithm("RSA-OAEP-512")

    @Serializable(with = JweAlgorithmSerializer::class)
    class UNKNOWN(identifier: String) : JweAlgorithm(identifier)

    override fun toString() = "${this::class.simpleName}(identifier='$identifier')"

    companion object : Enumeration<JweAlgorithm> {
        override val entries: Set<JweAlgorithm> by lazy {
            setOf(
                ECDH_ES,
                A128KW,
                A192KW,
                A256KW,
                A128GCMKW,
                A192GCMKW,
                A256GCMKW,
                RSA_OAEP_256,
                RSA_OAEP_384,
                RSA_OAEP_512,
            ) + HPKE.entries + HPKE_KE.entries
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is JweAlgorithm) return false
        if (identifier != other.identifier) return false
        return true
    }

    override fun hashCode(): Int {
        return identifier.hashCode()
    }
}

/**
 * Tries to map this algorithm to a matching [JsonWebAlgorithm] for key wrapping.
 * Mappings exist for the following algorithms (as others are not direct mappings of symmetric algorithms):
 * * [SymmetricEncryptionAlgorithm.AES.GCM]
 * * [SymmetricEncryptionAlgorithm.AES.WRAP]
 *
 *
 * @return `null` if no mapping exists
 */
fun SymmetricEncryptionAlgorithm<*, *, *>.toJweKwAlgorithm(): KmmResult<JweAlgorithm.Symmetric> = catching {
    when (this) {
        SymmetricEncryptionAlgorithm.AES_128.WRAP.RFC3394 -> JweAlgorithm.A128KW
        SymmetricEncryptionAlgorithm.AES_192.WRAP.RFC3394 -> JweAlgorithm.A192KW
        SymmetricEncryptionAlgorithm.AES_256.WRAP.RFC3394 -> JweAlgorithm.A256KW

        SymmetricEncryptionAlgorithm.AES_128.GCM -> JweAlgorithm.A128GCMKW
        SymmetricEncryptionAlgorithm.AES_192.GCM -> JweAlgorithm.A192GCMKW
        SymmetricEncryptionAlgorithm.AES_256.GCM -> JweAlgorithm.A256GCMKW

        else -> throw UnsupportedCryptoException("$this is not a a supported key wrapping algorithm for JWE")
    }
}

object JweAlgorithmSerializer : KSerializer<JweAlgorithm> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JweAlgorithmSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JweAlgorithm) =
        JwaSerializer.serialize(encoder, value)

    override fun deserialize(decoder: Decoder): JweAlgorithm {
        val decoded = decoder.decodeString()
        return catching { JweAlgorithm.entries.first { it.identifier == decoded } }.getOrElse {
            JweAlgorithm.UNKNOWN(decoded)
        }
    }

}