package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.ImplementationError
import at.asitplus.signum.indispensable.asn1.Identifiable
import at.asitplus.signum.indispensable.asn1.KnownOIDs
import at.asitplus.signum.indispensable.asn1.ObjectIdentifier
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MAC
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
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
sealed interface SymmetricEncryptionAlgorithm<out A : AuthCapability<out K>, out I : NonceTrait, out K : KeyType> :
    Identifiable {
    val authCapability: A

    /** Indicates if this algorithm requires a nonce.*/
    val nonceTrait: I

    override fun toString(): String

    companion object {
        //ChaCha20Poly1305 is already an object, so we don't need to redeclare here

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            @HazardousMaterials("ECB is almost always insecure!")
            val ECB = AES.ECB(keySize)

            val WRAP = WrapDefinition(keySize)

            class WrapDefinition(keySize: BitLength) {
                val RFC3394 = AES.WRAP.RFC3394(keySize)
            }

            class CbcDefinition(keySize: BitLength) {
                @HazardousMaterials("Unauthenticated!")
                val PLAIN = AES.CBC.Unauthenticated(keySize)

                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                class HmacDefinition(innerCipher: AES.CBC.Unauthenticated) {
                    val SHA_256 = AES.CBC.HMAC(innerCipher, HMAC.SHA256)
                    val SHA_384 = AES.CBC.HMAC(innerCipher, HMAC.SHA384)
                    val SHA_512 = AES.CBC.HMAC(innerCipher, HMAC.SHA512)

                    @HazardousMaterials("Insecure hash function!")
                    val SHA_1 = AES.CBC.HMAC(innerCipher, HMAC.SHA1)
                }
            }
        }
    }

    /**Humanly-readable name**/
    val name: String

    /**
     * Key length
     */
    val keySize: BitLength

    //TODO: why are there ambiguities for sealed box creation?
    sealed interface Unauthenticated<out I : NonceTrait> :
        SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I, KeyType.Integrated> {
        companion object
    }

    sealed interface Authenticated<out A : AuthCapability.Authenticated<out K>, out I : NonceTrait, out K : KeyType> :
        SymmetricEncryptionAlgorithm<A, I, K> {
        interface Integrated<I : NonceTrait> :
            Authenticated<AuthCapability.Authenticated.Integrated, I, KeyType.Integrated>

        interface WithDedicatedMac<M : MAC, I : NonceTrait> :
            Authenticated<AuthCapability.Authenticated.WithDedicatedMac<M, I>, I, KeyType.WithDedicatedMacKey>
    }

    sealed interface RequiringNonce<out A : AuthCapability<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, NonceTrait.Required, K>

    sealed interface WithoutNonce<out A : AuthCapability<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, NonceTrait.Without, K>

    /**
     * Advanced Encryption Standard
     */
    sealed class AES<I : NonceTrait, K : KeyType, A : AuthCapability<K>>(
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
            override val nonceTrait = NonceTrait.Required(96.bit)
            override val authCapability = AuthCapability.Authenticated.Integrated(blockSize)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw ImplementationError("AES GCM OID")
            }
        }

        sealed class WRAP(keySize: BitLength) :
            AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(ModeOfOperation.ECB, keySize),
            SymmetricEncryptionAlgorithm.WithoutNonce<AuthCapability.Unauthenticated, KeyType.Integrated>,
            SymmetricEncryptionAlgorithm.Unauthenticated<NonceTrait.Without> {
            override val authCapability = AuthCapability.Unauthenticated

            /**
             * Key Wrapping as per [RFC 3394](https://datatracker.ietf.org/doc/rfc3394/)
             * Key must be at least 16 bytes and a multiple of 8 bytes
             */
            class RFC3394(keySize: BitLength) : WRAP(keySize) {
                override val nonceTrait = NonceTrait.Without
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
            override val nonceTrait = NonceTrait.Without
            override val authCapability = AuthCapability.Unauthenticated
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw ImplementationError("AES ECB OID")
            }
        }

        sealed class CBC<K : KeyType, A : AuthCapability<K>>(keySize: BitLength) :
            AES<NonceTrait.Required, K, A>(ModeOfOperation.CBC, keySize) {
            override val nonceTrait = NonceTrait.Required(128u.bit)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw ImplementationError("AES CBC OID")
            }

            class Unauthenticated(
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
                innerCipher: Unauthenticated,
                mac: at.asitplus.signum.indispensable.mac.HMAC,
                dedicatedMacInputCalculation: DedicatedMacInputCalculation
            ) : SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, NonceTrait.Required>,
                SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, NonceTrait.Required>, KeyType.WithDedicatedMacKey>,
                CBC<KeyType.WithDedicatedMacKey, AuthCapability.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, NonceTrait.Required>>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: at.asitplus.signum.indispensable.mac.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultDedicatedMacInputCalculation
                )

                override val authCapability =
                    AuthCapability.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, NonceTrait.Required>(
                        innerCipher,
                        mac,
                        innerCipher.keySize,
                        mac.outputLength,
                        dedicatedMacInputCalculation
                    )
                override val name = super.name + " $mac"

                /**
                 * Instantiates a new [CBC.HMAC] instance with a custom [DedicatedMacInputCalculation]
                 */
                fun Custom(dedicatedMacInputCalculation: DedicatedMacInputCalculation) =
                    CBC.HMAC(
                        authCapability.innerCipher as Unauthenticated,
                        authCapability.mac,
                        dedicatedMacInputCalculation
                    )
            }
        }
    }

    /**
     * ChaCha20 with Poly-1305 AEAD stream cipher
     */
    object ChaCha20Poly1305 :
        StreamCipher<AuthCapability.Authenticated.Integrated, NonceTrait.Required, KeyType.Integrated>(),
        SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
        SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated> {
        override val authCapability = AuthCapability.Authenticated.Integrated(128u.bit)
        override val nonceTrait = NonceTrait.Required(96u.bit)
        override val name: String = "ChaCha20-Poly1305"
        override fun toString() = name
        override val keySize = 256u.bit
        override val oid = KnownOIDs.chaCha20Poly1305
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface AuthCapability<K : KeyType> {
    /**
     * accessor to get the key type due to type erasure
     */
    val keyType: K

    /**
     * Indicates an authenticated cipher
     */
    sealed class Authenticated<K : KeyType>(val tagLength: BitLength, override val keyType: K) : AuthCapability<K> {

        /**
         * An authenticated cipher construction that is inherently authenticated and thus permits no dedicated MAC key
         */
        class Integrated(tagLen: BitLength) : Authenticated<KeyType.Integrated>(tagLen, KeyType.Integrated)

        /**
         * An authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function, requiring a dedicated MAC key.
         * _Encrypt-then-MAC_
         */
        class WithDedicatedMac<M : MAC, I : NonceTrait>(
            /**
             * The inner unauthenticated cipher
             */
            val innerCipher: SymmetricEncryptionAlgorithm<Unauthenticated, I, KeyType.Integrated>,
            /**
             * The mac function used to provide authenticated encryption
             */
            val mac: M,
            /**
             * The preferred length pf the MAC key. Can be overridden during key generation and is unconstrained.
             */
            val preferredMacKeyLength: BitLength,
            tagLen: BitLength,

            /**
             * Specifies how the inputs to the MAC are to be encoded/processed
             */
            val dedicatedMacInputCalculation: DedicatedMacInputCalculation
        ) : Authenticated<KeyType.WithDedicatedMacKey>(tagLen, KeyType.WithDedicatedMacKey) {

            override fun equals(other: Any?): Boolean {
                if (this === other) return true
                if (other !is WithDedicatedMac<*, *>) return false
                if (!super.equals(other)) return false

                if (innerCipher != other.innerCipher) return false
                if (mac != other.mac) return false
                if (preferredMacKeyLength != other.preferredMacKeyLength) return false
                if (dedicatedMacInputCalculation != other.dedicatedMacInputCalculation) return false

                return true
            }

            override fun hashCode(): Int {
                var result = super.hashCode()
                result = 31 * result + innerCipher.hashCode()
                result = 31 * result + mac.hashCode()
                result = 31 * result + preferredMacKeyLength.hashCode()
                result = 31 * result + dedicatedMacInputCalculation.hashCode()
                return result
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Authenticated<*>) return false

            if (tagLength != other.tagLength) return false
            if (keyType != other.keyType) return false

            return true
        }

        override fun hashCode(): Int {
            var result = tagLength.hashCode()
            result = 31 * result + keyType.hashCode()
            return result
        }
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : AuthCapability<KeyType.Integrated> {
        override val keyType = KeyType.Integrated
    }
}

/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
typealias DedicatedMacInputCalculation = MAC.(ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray) -> ByteArray

/**
 * The default dedicated mac input calculation as per [FRC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1), authenticating all inputs:
 * `AAD || IV || Ciphertext || AAD Length`, where AAD_length is a 64 bit big-endian
 */
val DefaultDedicatedMacInputCalculation: DedicatedMacInputCalculation =
    fun MAC.(ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
        aad + iv + ciphertext + aad.size.toLong().encodeTo8Bytes()

/**
 * Marker, indicating whether a symmetric encryption algorithms requires or prohibits the use of a nonce/IV
 */
sealed interface NonceTrait {
    /**
     * Indicates that a cipher requires an initialization vector
     */
    class Required(val length: BitLength) : NonceTrait

    object Without : NonceTrait
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
        CBC("Cipherblock Chaining Mode", "CBC"),
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
fun < A : AuthCapability<out K>,  I : NonceTrait,  K : KeyType>SymmetricEncryptionAlgorithm<A, I, K>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<*, *, *>)
        returns(false) implies (this@isBlockCipher is StreamCipher<*, *, *>)
    }
    return this is BlockCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isStreamCipherAlias")
@OptIn(ExperimentalContracts::class)
fun < A : AuthCapability<out K>,  I : NonceTrait,  K : KeyType>SymmetricEncryptionAlgorithm<A, I, K>.isStreamCipher(): Boolean {
    contract {
        returns(true) implies (this@isStreamCipher is StreamCipher<*, *, *>)
        returns(false) implies (this@isStreamCipher is BlockCipher<*, *, *>)
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
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, I>)
        returns(false) implies (
                (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Unauthenticated
                        || this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.Integrated<I>))
    }
    return this.authCapability is AuthCapability.Authenticated.WithDedicatedMac<*, *>
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
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, I>)

    }
    return this.authCapability is AuthCapability.Authenticated.Integrated
}


val SymmetricEncryptionAlgorithm<*,NonceTrait.Required,*>.nonceLength : BitLength get() = nonceTrait.length
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated.WithDedicatedMac<*,*>,*, KeyType.WithDedicatedMacKey>.preferredMacKeyLength : BitLength get() = authCapability.preferredMacKeyLength
val SymmetricEncryptionAlgorithm<AuthCapability.Authenticated<*>,*, *>.authTagLength : BitLength get() = authCapability.tagLength