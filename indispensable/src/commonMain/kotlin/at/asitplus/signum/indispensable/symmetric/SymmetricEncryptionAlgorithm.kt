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
import kotlin.jvm.JvmName


sealed interface SymmetricEncryptionAlgorithm<out A : AuthType<out K>, out I : Nonce, out K : KeyType> :
    Identifiable {
    val authCapability: A
    val nonce: I

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

            class WrapDefinition(keySize: BitLength){
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
     * Key length in bits
     */
    val keySize: BitLength

    //TODO: why are there ambiguities for sealed box creation?
    sealed interface Unauthenticated<out I : Nonce> :
        SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated> {
        companion object
    }

    sealed interface Authenticated<out A : AuthType.Authenticated<out K>, out I : Nonce, out K : KeyType> :
        SymmetricEncryptionAlgorithm<A, I, K> {
        interface Integrated<I : Nonce> :
            Authenticated<AuthType.Authenticated.Integrated, I, KeyType.Integrated>

        interface WithDedicatedMac<M : MAC, I : Nonce> :
            Authenticated<AuthType.Authenticated.WithDedicatedMac<M, I>, I, KeyType.WithDedicatedMacKey>
    }

    sealed interface RequiringNonce<out A : AuthType<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, Nonce.Required, K>
    sealed interface WithoutNonce<out A : AuthType<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, Nonce.Without, K>

    /**
     * Advanced Encryption Standard
     */
    sealed class AES<I : Nonce, K : KeyType, A : AuthType<K>>(
        modeOfOps: ModeOfOperation,
        override val keySize: BitLength
    ) :
        BlockCipher<A, I, K>(modeOfOps, blockSize = 128.bit),
        SymmetricEncryptionAlgorithm<A, I, K> {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            AES<Nonce.Required, KeyType.Integrated, AuthType.Authenticated.Integrated>(ModeOfOperation.GCM, keySize) {
            override val nonce = Nonce.Required(96.bit)
            override val authCapability = AuthType.Authenticated.Integrated(blockSize)
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class WRAP<I : Nonce>(keySize: BitLength) :
            SymmetricEncryptionAlgorithm.Unauthenticated<I>,
            AES<I, KeyType.Integrated, AuthType.Unauthenticated>(ModeOfOperation.ECB, keySize) {
            override val authCapability = AuthType.Unauthenticated

            /**
             * Key Wrapping as per [RFC 3394](https://datatracker.ietf.org/doc/rfc3394/)
             */
            class RFC3394(keySize: BitLength) : WRAP<Nonce.Without>(keySize)                {
                override val nonce = Nonce.Without
                override val oid: ObjectIdentifier = when (keySize.bits) {
                    128u -> KnownOIDs.aes128_wrap
                    192u -> KnownOIDs.aes192_wrap
                    256u -> KnownOIDs.aes256_wrap
                    else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
                }
            }
            //on request, add RFC 5649  key wrapping here. requires manual work, though
        }

        @HazardousMaterials("ECB is almost always insecure!")
        class ECB internal constructor(keySize: BitLength) :
            AES<Nonce.Without, KeyType.Integrated, AuthType.Unauthenticated>(ModeOfOperation.ECB, keySize) {
            override val nonce = Nonce.Without
            override val authCapability = AuthType.Unauthenticated
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw IllegalStateException("$keySize This is an implementation flaw. Report this bug!")
            }
        }

        sealed class CBC<K : KeyType, A : AuthType<K>>(keySize: BitLength) :
            AES<Nonce.Required, K, A>(ModeOfOperation.CBC, keySize) {
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
            ) :
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
        StreamCipher<AuthType.Authenticated.Integrated, Nonce.Required, KeyType.Integrated>() {
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

sealed interface Nonce {
    /**
     * Indicates that a cipher requires an initialization vector
     */
    class Required(val length: BitLength) : Nonce

    object Without : Nonce
}

abstract class BlockCipher<A : AuthType<K>, I : Nonce, K : KeyType>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I, K> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipherblock Chaining Mode", "CBC"),
        ECB("Electronic Codebook Mode", "ECB"),
    }
}

abstract class StreamCipher<A : AuthType<K>, I : Nonce, K : KeyType> : SymmetricEncryptionAlgorithm<A, I, K>


//Here come the contracts!

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipherAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *, *>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<*, *, *>)
        returns(false) implies (this@isBlockCipher is StreamCipher<*, *, *>)
    }
    return this is BlockCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *, *>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<*, *, *>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<*>)
    }
    return this.authCapability is AuthType.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, *>)
        returns(false) implies (
                (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Unauthenticated
                        || this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.Integrated))
    }
    return this.authCapability is AuthType.Authenticated.WithDedicatedMac<*, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *, *>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce<*, *>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce<*, *>)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegrated")
@OptIn(ExperimentalContracts::class)
fun <I : Nonce> SymmetricEncryptionAlgorithm.Authenticated<*, I, *>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.Integrated<I>)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, I>)
    }
    return this.authCapability is AuthType.Authenticated.Integrated
}
