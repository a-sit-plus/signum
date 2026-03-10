package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.AlgorithmRegistry
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HmacAlgorithm
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.internals.ImplementationError
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract
import kotlin.jvm.JvmName

/**
 * Base interface for every symmetric encryption algorithm. A Symmetric encryption algorithm is characterised by:
 * * an [authCapability] ([AuthCapability.Unauthenticated], [AuthCapability.Authenticated.Integrated], [AuthCapability.Authenticated.WithDedicatedMac]
 * * a [KeyType] ([KeyType.Integrated], [KeyType.WithDedicatedMacKey])
 * * its [nonceTrait] ([NonceTrait.Required], [NonceTrait.Without])
 * * the [keySize]
 * * its [name]
 */
interface SymmetricEncryptionAlgorithm<out A : AuthCapability<out K>, out I : NonceTrait, out K : KeyType> :
    Identifiable, Enumerable {
    val authCapability: A

    /** Indicates if this algorithm requires a nonce.*/
    val nonceTrait: I

    override fun toString(): String

    companion object : Enumeration<SymmetricEncryptionAlgorithm<*, *, *>> {

        private val builtIns: List<SymmetricEncryptionAlgorithm<*, *, *>> by lazy {
            (listOf(ChaCha20Poly1305Algorithm) + AES_128.entries + AES_192.entries + AES_256.entries)
                .onEach { AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(it) }
        }

        override val entries: List<SymmetricEncryptionAlgorithm<*, *, *>>
            get() {
                builtIns
                return AlgorithmRegistry.symmetricEncryptionAlgorithms
            }

        val ChaCha20Poly1305 get() = ChaCha20Poly1305Algorithm

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        val AES_128_GCM get() = AES_128.GCM
        val AES_192_GCM get() = AES_192.GCM
        val AES_256_GCM get() = AES_256.GCM
        @OptIn(HazardousMaterials::class) val AES_128_ECB get() = AES_128.ECB
        @OptIn(HazardousMaterials::class) val AES_192_ECB get() = AES_192.ECB
        @OptIn(HazardousMaterials::class) val AES_256_ECB get() = AES_256.ECB
        @OptIn(HazardousMaterials::class) val AES_128_CBC_PLAIN get() = AES_128.CBC.PLAIN
        @OptIn(HazardousMaterials::class) val AES_192_CBC_PLAIN get() = AES_192.CBC.PLAIN
        @OptIn(HazardousMaterials::class) val AES_256_CBC_PLAIN get() = AES_256.CBC.PLAIN
        @OptIn(HazardousMaterials::class) val AES_128_CBC_HMAC_SHA256 get() = AES_128.CBC.HMAC.SHA_256
        @OptIn(HazardousMaterials::class) val AES_192_CBC_HMAC_SHA256 get() = AES_192.CBC.HMAC.SHA_256
        @OptIn(HazardousMaterials::class) val AES_256_CBC_HMAC_SHA256 get() = AES_256.CBC.HMAC.SHA_256
        @OptIn(HazardousMaterials::class) val AES_128_CBC_HMAC_SHA384 get() = AES_128.CBC.HMAC.SHA_384
        @OptIn(HazardousMaterials::class) val AES_192_CBC_HMAC_SHA384 get() = AES_192.CBC.HMAC.SHA_384
        @OptIn(HazardousMaterials::class) val AES_256_CBC_HMAC_SHA384 get() = AES_256.CBC.HMAC.SHA_384
        @OptIn(HazardousMaterials::class) val AES_128_CBC_HMAC_SHA512 get() = AES_128.CBC.HMAC.SHA_512
        @OptIn(HazardousMaterials::class) val AES_192_CBC_HMAC_SHA512 get() = AES_192.CBC.HMAC.SHA_512
        @OptIn(HazardousMaterials::class) val AES_256_CBC_HMAC_SHA512 get() = AES_256.CBC.HMAC.SHA_512
        val AES_128_WRAP_RFC3394 get() = AES_128.WRAP.RFC3394
        val AES_192_WRAP_RFC3394 get() = AES_192.WRAP.RFC3394
        val AES_256_WRAP_RFC3394 get() = AES_256.WRAP.RFC3394

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) : Enumeration<SymmetricEncryptionAlgorithm<*, *, *>> {

            @OptIn(HazardousMaterials::class)
            override val entries: List<SymmetricEncryptionAlgorithm<*, *, *>> by lazy {
                listOf(GCM, ECB) + CBC.entries + WRAP.entries
            }

            /**
             * AES in Galois Counter Mode
             */
            val GCM = AesGcmAlgorithm(keySize)

            /**
             * AES in Cipher Block Chaining Mode
             */
            val CBC = CbcDefinition(keySize)

            /**
             * AES in Electronic Codebook Mode. You almost certainly don't want to use this
             */
            @HazardousMaterials("ECB is almost always insecure!")
            val ECB = AesEcbAlgorithm(keySize)

            /**
             * AES Key Wrapping as per [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)
             */
            val WRAP = WrapDefinition(keySize)

            class WrapDefinition(keySize: BitLength) : Enumeration<SymmetricEncryptionAlgorithm<*, *, *>> {
                override val entries: List<SymmetricEncryptionAlgorithm<*, *, *>> by lazy { listOf(RFC3394) }
                val RFC3394 = AesWrapAlgorithm(keySize)
            }

            class CbcDefinition(keySize: BitLength) : Enumeration<SymmetricEncryptionAlgorithm<*, *, *>> {
                @OptIn(HazardousMaterials::class)
                override val entries: List<SymmetricEncryptionAlgorithm<*, *, *>> by lazy {
                    listOf(PLAIN) + MessageAuthenticationCode.entries.filterIsInstance<HmacAlgorithm>()
                        .map { AesCbcHmacAlgorithm(PLAIN, it) }
                }
                /**
                 * Plain, Unauthenticated AES in Cipher Block Chaining mode.
                 * You almost certainly don't want to use this as is, but rather some [HMAC]-authenticated variant
                 */
                @HazardousMaterials("Unauthenticated!")
                val PLAIN = AesCbcAlgorithm(keySize)

                /**
                 * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                 */
                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                /**
                 * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                 */
                class HmacDefinition(innerCipher: AesCbcAlgorithm) :
                    Enumeration<AesCbcHmacAlgorithm> {
                    @OptIn(HazardousMaterials::class)
                    override val entries: List<AesCbcHmacAlgorithm> by lazy { listOf(SHA_256, SHA_384, SHA_512, SHA_1) }
                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_256 = AesCbcHmacAlgorithm(innerCipher, HmacAlgorithm(Digest.SHA256))

                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_384 = AesCbcHmacAlgorithm(innerCipher, HmacAlgorithm(Digest.SHA384))

                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_512 = AesCbcHmacAlgorithm(innerCipher, HmacAlgorithm(Digest.SHA512))

                    @HazardousMaterials("Insecure hash function!")
                    val SHA_1 = AesCbcHmacAlgorithm(innerCipher, HmacAlgorithm(Digest.SHA1))
                }
            }
        }
    }

    /**Human-readable name**/
    val name: String

    /**
     * Key length
     */
    val keySize: BitLength

    interface Unauthenticated<out I : NonceTrait> :
        SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated> {

        override val authCapability get() = AuthCapability.Unauthenticated
    }

    interface Authenticated<out A : AuthCapability.Authenticated<out K>, out I : NonceTrait, out K : KeyType> :
        SymmetricEncryptionAlgorithm<A, I, K> {

        val authTagSize: BitLength

        interface Integrated<I : NonceTrait> :
            Authenticated<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>
        {
            override val authCapability get() = AuthCapability.Authenticated.Integrated
        }

        interface EncryptThenMAC<M : MessageAuthenticationCode, I : NonceTrait> :
            Authenticated<AuthCapability.Authenticated.WithDedicatedMac, I, KeyType.WithDedicatedMacKey>
        {
            override val authCapability get() = AuthCapability.Authenticated.WithDedicatedMac

            val innerCipher: SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated>
            /**
             * The mac function used to provide authenticated encryption
             */
            val mac: M

            /**
             * The preferred length pf the MAC key. Can be overridden during key generation and is unconstrained.
             */
            val preferredMacKeyLength: BitLength

            /**
             * Specifies how the inputs to the MAC are to be encoded/processed
             */
            val macInputCalculation: MacInputCalculation

            /**
             * Specifies how the inputs to the MAC are to be encoded/processed
             */
            val macAuthTagTransform: MacAuthTagTransformation

        }
    }

    interface RequiringNonce<out A : AuthCapability<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>
    {
        override val nonceTrait get() = NonceTrait.Required
        val nonceSize: BitLength
    }

    interface WithoutNonce<out A : AuthCapability<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K>
    {
        override val nonceTrait get() = NonceTrait.Without
    }

    /**
     * Advanced Encryption Standard
     */
    abstract class AES<I : NonceTrait, K : KeyType, A : AuthCapability<K>>(
        modeOfOps: ModeOfOperation,
        override val keySize: BitLength
    ) :
        BlockCipher<A, I, K>(modeOfOps, blockSize = 128.bit),
        SymmetricEncryptionAlgorithm<A, I, K> {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
            SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>,
            AES<NonceTrait.Required, KeyType.Integrated, AuthCapability.Authenticated.Integrated>(
                ModeOfOperation.GCM,
                keySize
            ) {
            override val nonceSize = 96.bit
            override val authTagSize = blockSize
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw ImplementationError("AES GCM OID")
            }
        }

        abstract class WRAP(keySize: BitLength) :
            AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(ModeOfOperation.ECB, keySize),
            SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
            SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without> {

            /**
             * Key Wrapping as per [RFC 3394](https://datatracker.ietf.org/doc/rfc3394/)
             * Key must be at least 16 bytes and a multiple of 8 bytes
             */
            class RFC3394 internal constructor(keySize: BitLength) : WRAP(keySize) {
                override val oid: ObjectIdentifier = when (keySize.bits) {
                    128u -> KnownOIDs.aes128_wrap
                    192u -> KnownOIDs.aes192_wrap
                    256u -> KnownOIDs.aes256_wrap
                    else -> throw ImplementationError("AES WRAP RFC3394 OID")
                }
            }
            //on request, add RFC 5649  key wrapping here. requires manual work, though
        }

        @HazardousMaterials("ECB is almost always insecure!")
        class ECB internal constructor(keySize: BitLength) :
            AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(ModeOfOperation.ECB, keySize),
            SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
            SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without> {
            override val authCapability = AuthCapability.Unauthenticated
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw ImplementationError("AES ECB OID")
            }
        }

        abstract class CBC<K : KeyType, A : AuthCapability<K>>(keySize: BitLength) :
            AES<NonceTrait.Required, K, A>(ModeOfOperation.CBC, keySize) {
            /*override*/ val nonceSize = 128u.bit
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw ImplementationError("AES CBC OID")
            }

            class Unauthenticated internal constructor(
                keySize: BitLength
            ) : CBC<KeyType.Integrated, AuthCapability.Unauthenticated>(keySize),
                SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
                SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Required> {
                override val authCapability = AuthCapability.Unauthenticated
                override val name = super.name + " Plain"
            }

            /**
             * AEAD-capabilities bolted onto AES-CBC
             */
            class HMAC
            private constructor(
                override val innerCipher: Unauthenticated,
                override val mac: HmacAlgorithm,
                override val macInputCalculation: MacInputCalculation,
                override val macAuthTagTransform: MacAuthTagTransformation,
                override val authTagSize: BitLength
            ) : SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<HmacAlgorithm, NonceTrait.Required>,
                SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac, KeyType.WithDedicatedMacKey>,
                CBC<KeyType.WithDedicatedMacKey, AuthCapability.Authenticated.WithDedicatedMac>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: HmacAlgorithm) : this(
                    innerCipher,
                    mac,
                    DefaultMacInputCalculation,
                    DefaultMacAuthTagTransformation,
                    authTagSize = BitLength(mac.outputLength.bits / 2u)
                )

                override val name = super.name + " $mac"
                override val preferredMacKeyLength: BitLength get() = innerCipher.keySize

                /**
                 * Instantiates a new [CBC.HMAC] instance with
                 * * custom [tagLength]
                 * * custom [MacInputCalculation]
                 */
                fun Custom(
                    tagLength: BitLength,
                    dedicatedMacInputCalculation: MacInputCalculation
                ) = Custom(tagLength, DefaultMacAuthTagTransformation, dedicatedMacInputCalculation)

                /**
                 * Instantiates a new [CBC.HMAC] instance with
                 * * custom [tagLength]
                 * * custom [dedicatedMacAuthTagTransformation]
                 * * custom [MacInputCalculation]
                 */
                fun Custom(
                    tagLength: BitLength,
                    dedicatedMacAuthTagTransformation: MacAuthTagTransformation,
                    dedicatedMacInputCalculation: MacInputCalculation
                ) = CBC.HMAC(
                    innerCipher,
                    mac,
                    dedicatedMacInputCalculation,
                    dedicatedMacAuthTagTransformation,
                    tagLength
                )
            }
        }
    }

    /**
     * ChaCha20 with Poly-1305 AEAD stream cipher
     */
}

class AesGcmAlgorithm internal constructor(keySize: BitLength) :
    SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>,
    SymmetricEncryptionAlgorithm.AES<NonceTrait.Required, KeyType.Integrated, AuthCapability.Authenticated.Integrated>(
        BlockCipher.ModeOfOperation.GCM,
        keySize
    ) {
    override val nonceSize = 96.bit
    override val authTagSize = blockSize
    override val oid: ObjectIdentifier = when (keySize.bits) {
        128u -> KnownOIDs.aes128_GCM
        192u -> KnownOIDs.aes192_GCM
        256u -> KnownOIDs.aes256_GCM
        else -> throw ImplementationError("AES GCM OID")
    }
}

abstract class AesWrapBase(keySize: BitLength) :
    SymmetricEncryptionAlgorithm.AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(
        BlockCipher.ModeOfOperation.ECB,
        keySize
    ),
    SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
    SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without>

class AesWrapAlgorithm internal constructor(keySize: BitLength) : AesWrapBase(keySize) {
    override val oid: ObjectIdentifier = when (keySize.bits) {
        128u -> KnownOIDs.aes128_wrap
        192u -> KnownOIDs.aes192_wrap
        256u -> KnownOIDs.aes256_wrap
        else -> throw ImplementationError("AES WRAP RFC3394 OID")
    }
}

@HazardousMaterials("ECB is almost always insecure!")
class AesEcbAlgorithm internal constructor(keySize: BitLength) :
    SymmetricEncryptionAlgorithm.AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(
        BlockCipher.ModeOfOperation.ECB,
        keySize
    ),
    SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
    SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without> {
    override val authCapability = AuthCapability.Unauthenticated
    override val oid: ObjectIdentifier = when (keySize.bits) {
        128u -> KnownOIDs.aes128_ECB
        192u -> KnownOIDs.aes192_ECB
        256u -> KnownOIDs.aes256_ECB
        else -> throw ImplementationError("AES ECB OID")
    }
}

abstract class AesCbcBase<K : KeyType, A : AuthCapability<K>>(keySize: BitLength) :
    SymmetricEncryptionAlgorithm.AES<NonceTrait.Required, K, A>(
        BlockCipher.ModeOfOperation.CBC,
        keySize
    ) {
    val nonceSize = 128u.bit
    override val oid: ObjectIdentifier = when (keySize.bits) {
        128u -> KnownOIDs.aes128_CBC
        192u -> KnownOIDs.aes192_CBC
        256u -> KnownOIDs.aes256_CBC
        else -> throw ImplementationError("AES CBC OID")
    }
}

class AesCbcAlgorithm internal constructor(keySize: BitLength) :
    AesCbcBase<KeyType.Integrated, AuthCapability.Unauthenticated>(keySize),
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
    SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Required> {
    override val authCapability = AuthCapability.Unauthenticated
    override val name = super.name + " Plain"
}

class AesCbcHmacAlgorithm internal constructor(
    override val innerCipher: AesCbcAlgorithm,
    override val mac: HmacAlgorithm,
    override val macInputCalculation: MacInputCalculation,
    override val macAuthTagTransform: MacAuthTagTransformation,
    override val authTagSize: BitLength
) : SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<HmacAlgorithm, NonceTrait.Required>,
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac, KeyType.WithDedicatedMacKey>,
    AesCbcBase<KeyType.WithDedicatedMacKey, AuthCapability.Authenticated.WithDedicatedMac>(innerCipher.keySize) {

    constructor(innerCipher: AesCbcAlgorithm, mac: HmacAlgorithm) : this(
        innerCipher,
        mac,
        DefaultMacInputCalculation,
        DefaultMacAuthTagTransformation,
        BitLength(mac.outputLength.bits / 2u)
    )

    override val name = super.name + " $mac"
    override val preferredMacKeyLength: BitLength get() = innerCipher.keySize

    fun Custom(
        tagLength: BitLength,
        dedicatedMacInputCalculation: MacInputCalculation
    ) = Custom(tagLength, DefaultMacAuthTagTransformation, dedicatedMacInputCalculation)

    fun Custom(
        tagLength: BitLength,
        dedicatedMacAuthTagTransformation: MacAuthTagTransformation,
        dedicatedMacInputCalculation: MacInputCalculation
    ) = AesCbcHmacAlgorithm(
        innerCipher,
        mac,
        dedicatedMacInputCalculation,
        dedicatedMacAuthTagTransformation,
        tagLength
    )
}

object ChaCha20Poly1305Algorithm :
    StreamCipher<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated>(),
    SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated> {
    override val authTagSize = 128u.bit
    override val nonceSize = 96u.bit
    override val name: String = "ChaCha20-Poly1305"
    override fun toString() = name
    override val keySize = 256u.bit
    override val oid = KnownOIDs.chaCha20Poly1305

    init {
        AlgorithmRegistry.registerSymmetricEncryptionAlgorithm(this)
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
interface AuthCapability<K : KeyType> {
    /**
     * accessor to get the key type due to type erasure
     */
    val keyType: K

    /**
     * Indicates an authenticated cipher
     */
    open class Authenticated<K : KeyType>(override val keyType: K) : AuthCapability<K> {

        /**
         * An authenticated cipher construction that is inherently authenticated and thus permits no dedicated MAC key
         */
        data object Integrated : Authenticated<KeyType.Integrated>(KeyType.Integrated)

        /**
         * An _Encrypt-then-MAC_ authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function, requiring a dedicated MAC key.
         */
        data object WithDedicatedMac : Authenticated<KeyType.WithDedicatedMacKey>(KeyType.WithDedicatedMacKey)
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : AuthCapability<KeyType.Integrated> {
        override val keyType get() = KeyType.Integrated
    }
}

/**
 * Typealias defining the signature of the lambda for processing the MAC output into an auth tag.
 */
typealias MacAuthTagTransformation = SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*,*>.(macOutput: ByteArray) -> ByteArray


/**
 * The default dedicated mac output transform as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1),
 * taking the first [authTagSize] many bytes of the MAC output as auth tag.
 */
val DefaultMacAuthTagTransformation: MacAuthTagTransformation =
    fun SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*,*>.(
        macOutput: ByteArray
    ): ByteArray = macOutput.take(this.authTagSize.bytes.toInt()).toByteArray()

/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
typealias MacInputCalculation = SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*,*>.(ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray) -> ByteArray

/**
 * The default dedicated mac input calculation as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1), authenticating all inputs:
 * `AAD || IV || Ciphertext || AAD Length`, where AAD_length is a 64 bit big-endian representation of the aad length in bits
 */
val DefaultMacInputCalculation: MacInputCalculation =
    fun SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*,*>.(ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
        aad + iv + ciphertext + (aad.size.toLong() * 8L).encodeTo8Bytes()

/**
 * Marker, indicating whether a symmetric encryption algorithms requires or prohibits the use of a nonce/IV
 */
interface NonceTrait {
    data object Required : NonceTrait
    data object Without : NonceTrait
}


/**
 * Marker interface indicating a block cipher. Purely informational
 */
abstract class BlockCipher<A : AuthCapability<K>, I : NonceTrait, K : KeyType>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I, K> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipher Block Chaining Mode", "CBC"),
        ECB("Electronic Codebook Mode", "ECB"),
    }
}

/**
 * Marker interface indicating a block cipher. Purely informational
 */
abstract class StreamCipher<A : AuthCapability<K>, I : NonceTrait, K : KeyType> : SymmetricEncryptionAlgorithm<A, I, K>


//Here come the contracts!

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipherAlias")
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<A, I, K>)
        returns(false) implies (this@isBlockCipher is StreamCipher<A, I, K>)
    }
    return this is BlockCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isStreamCipherAlias")
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<out K>, I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<A, I, K>.isStreamCipher(): Boolean {
    contract {
        returns(true) implies (this@isStreamCipher is StreamCipher<A, I, K>)
        returns(false) implies (this@isStreamCipher is BlockCipher<A, I, K>)
    }
    return this is StreamCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedAlias")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait, K : KeyType> SymmetricEncryptionAlgorithm<*, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<*, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<I>)
    }
    return this.authCapability is AuthCapability.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacAlias")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<*, I, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*, I>)
        returns(false) implies (
                (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Unauthenticated
                        || this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.Integrated<I>))
    }
    return this.authCapability is AuthCapability.Authenticated.WithDedicatedMac
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAlias")
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<out K>, K : KeyType> SymmetricEncryptionAlgorithm<A, *, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce<A, K>)
    }
    return this.nonceTrait is NonceTrait.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegrated")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait> SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, I, *>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.Integrated<I>)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*, I>)

    }
    return this.authCapability is AuthCapability.Authenticated.Integrated
}


val SymmetricEncryptionAlgorithm<*, NonceTrait.Required, *>.nonceSize: BitLength get() = (this as SymmetricEncryptionAlgorithm.RequiringNonce<*,*>).nonceSize
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac, *, KeyType.WithDedicatedMacKey>.preferredMacKeyLength: BitLength get() = (this as SymmetricEncryptionAlgorithm.Authenticated.EncryptThenMAC<*,*>).preferredMacKeyLength
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>, *, *>.authTagSize: BitLength get() = (this as SymmetricEncryptionAlgorithm.Authenticated).authTagSize

interface SpecializedSymmetricEncryptionAlgorithm {
    val algorithm: SymmetricEncryptionAlgorithm<*,*,*>
}
