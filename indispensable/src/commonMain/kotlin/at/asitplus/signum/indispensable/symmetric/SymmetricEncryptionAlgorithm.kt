package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
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


sealed interface SymmetricEncryptionAlgorithm<out A : AuthType<out K>, out I : Nonce, out K : KeyType> :
    Identifiable {
    val authCapability: A
    val nonce: I

    override fun toString(): String

    companion object {
        //ChaChaPoly is already an object, so we don't need to redeclare here

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) {

            val GCM = AES.GCM(keySize)
            val CBC = CbcDefinition(keySize)

            class CbcDefinition(keySize: BitLength) {
                @HazardousMaterials
                val PLAIN = AES.CBC.Unauthenticated(keySize)

                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                class HmacDefinition(innerCipher: AES.CBC.Unauthenticated) {
                    val SHA_256 = AES.CBC.HMAC(innerCipher, HMAC.SHA256)
                    val SHA_384 = AES.CBC.HMAC(innerCipher, HMAC.SHA384)
                    val SHA_512 = AES.CBC.HMAC(innerCipher, HMAC.SHA512)
                    val SHA_1 = AES.CBC.HMAC(innerCipher, HMAC.SHA1)
                }
            }
        }
    }

    /**Humanly-readable name**/
    val name: String

    /**
     * Key length in bits
     */
    val keySize: BitLength

    interface Unauthenticated<out I : Nonce> :
        SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated>

    sealed interface Authenticated<out A : AuthType.Authenticated<out K>, out I : Nonce, out K : KeyType> :
        SymmetricEncryptionAlgorithm<A, I, K> {
        interface Integrated<I : Nonce> :
            Authenticated<AuthType.Authenticated.Integrated, I, KeyType.Integrated>

        interface WithDedicatedMac<M : MAC, I : Nonce> :
            Authenticated<AuthType.Authenticated.WithDedicatedMac<M, I>, I, KeyType.WithDedicatedMacKey>
    }

    interface RequiringNonce<out A : AuthType<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, Nonce.Required, K>

    interface WithoutNonce<out A : AuthType<out K>, K : KeyType> : SymmetricEncryptionAlgorithm<A, Nonce.Without, K>

    /**
     * Advanced Encryption Standard
     */
    sealed class AES<K : KeyType, A : AuthType<K>>(modeOfOps: ModeOfOperation, override val keySize: BitLength) :
        BlockCipher<A, Nonce.Required, K>(modeOfOps, blockSize = 128.bit) {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            SymmetricEncryptionAlgorithm.Authenticated.Integrated<Nonce.Required>,
            RequiringNonce<AuthType.Authenticated.Integrated, KeyType.Integrated>,
            AES<KeyType.Integrated, AuthType.Authenticated.Integrated>(ModeOfOperation.GCM, keySize) {
            override val nonce = Nonce.Required(96.bit)
            override val authCapability = AuthType.Authenticated.Integrated(blockSize)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<K : KeyType, A : AuthType<K>>(keySize: BitLength) :
            RequiringNonce<A, K>,
            AES<K, A>(ModeOfOperation.CBC, keySize) {
            override val nonce = Nonce.Required(128u.bit)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }

            class Unauthenticated(
                keySize: BitLength
            ) : CBC<KeyType.Integrated, AuthType.Unauthenticated>(keySize),
                SymmetricEncryptionAlgorithm.Unauthenticated<Nonce.Required> {
                override val authCapability = AuthType.Unauthenticated
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
            ) : SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, Nonce.Required>,
                CBC<KeyType.WithDedicatedMacKey, AuthType.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, Nonce.Required>>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: at.asitplus.signum.indispensable.mac.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultDedicatedMacInputCalculation
                )

                override val authCapability =
                    AuthType.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC, Nonce.Required>(
                        innerCipher,
                        mac,
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

    object ChaCha20Poly1305 :
        StreamCipher<AuthType.Authenticated<KeyType.Integrated>, Nonce.Required, KeyType.Integrated>() {
        override val authCapability = AuthType.Authenticated.Integrated(128u.bit)
        override val nonce = Nonce.Required(96u.bit)
        override val name: String = "ChaCha20-Poly1305"
        override fun toString() = name
        override val keySize = 256u.bit
        override val oid = KnownOIDs.chaCha20Poly1305
    }
}

/**
 * Defines whether a cipher is authenticated or not
 */
sealed interface AuthType<K : KeyType> {
    /**
     * accessor to get the key type due to type erasure
     */
    val keyType: K

    /**
     * Indicates an authenticated cipher
     */
    sealed class Authenticated<K : KeyType>(val tagLen: BitLength, override val keyType: K) : AuthType<K> {

        /**
         * An authenticated cipher construction that is inherently authenticated
         */
        class Integrated(tagLen: BitLength) : Authenticated<KeyType.Integrated>(tagLen, KeyType.Integrated)

        /**
         * An authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function.
         */
        class WithDedicatedMac<M : MAC, I : Nonce>(
            val innerCipher: SymmetricEncryptionAlgorithm<Unauthenticated, I, KeyType.Integrated>,
            val mac: M,
            tagLen: BitLength,
            val dedicatedMacInputCalculation: DedicatedMacInputCalculation
        ) : Authenticated<KeyType.WithDedicatedMacKey>(tagLen, KeyType.WithDedicatedMacKey)
    }

    /**
     * Indicates an unauthenticated cipher
     */
    object Unauthenticated : AuthType<KeyType.Integrated> {
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

sealed class Nonce {
    /**
     * Indicates that a cipher requires an initialization vector
     */
    class Required(val length: BitLength) : Nonce()

    object Without : Nonce()
}

abstract class BlockCipher<A : AuthType<K>, I : Nonce, K : KeyType>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I, K> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
    }
}

abstract class StreamCipher<A : AuthType<K>, I : Nonce, K : KeyType> : SymmetricEncryptionAlgorithm<A, I, K>

@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricEncryptionAlgorithm<A, I, K>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<A, I, K>)
        returns(false) implies (this@isBlockCipher is StreamCipher<A, I, K>)
    }
    return this is BlockCipher<*, *, *>
}

@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricEncryptionAlgorithm<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<A, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<I>)
    }
    return this.authCapability is AuthType.Authenticated<*>
}


@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricEncryptionAlgorithm<A, I, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce<A, K>)
    }
    return this.nonce is Nonce.Required
}

