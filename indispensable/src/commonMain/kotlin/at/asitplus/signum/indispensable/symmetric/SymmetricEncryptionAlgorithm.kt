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

    sealed interface Unauthenticated<out I : Nonce> :
        SymmetricEncryptionAlgorithm<AuthType.Unauthenticated, I, KeyType.Integrated>

    sealed interface Authenticated<out A : AuthType.Authenticated<out K>, out I : Nonce, out K : KeyType> :
        SymmetricEncryptionAlgorithm<A, I, K> {
        interface Integrated<I : Nonce> :
            Authenticated<AuthType.Authenticated.Integrated, I, KeyType.Integrated>

        interface WithDedicatedMac<M : MAC, I : Nonce> :
            Authenticated<AuthType.Authenticated.WithDedicatedMac<M, I>, I, KeyType.WithDedicatedMacKey>
    }

    sealed interface RequiringNonce<out A : AuthType<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, Nonce.Required, K> {
        sealed interface Unauthenticated :
            RequiringNonce<AuthType.Unauthenticated, KeyType.Integrated>,
            SymmetricEncryptionAlgorithm.Unauthenticated<Nonce.Required>

        sealed interface Authenticated<out A : AuthType.Authenticated<out K>, out K : KeyType> :
            SymmetricEncryptionAlgorithm.Authenticated<A, Nonce.Required, K> {
            interface Integrated :
                Authenticated<AuthType.Authenticated.Integrated, KeyType.Integrated>,
                RequiringNonce<AuthType.Authenticated.Integrated, KeyType.Integrated>,
                SymmetricEncryptionAlgorithm.Authenticated.Integrated<Nonce.Required>

            interface WithDedicatedMac<M : MAC> :
                Authenticated<AuthType.Authenticated.WithDedicatedMac<M, Nonce.Required>, KeyType.WithDedicatedMacKey>,
                RequiringNonce<AuthType.Authenticated.WithDedicatedMac<M, Nonce.Required>, KeyType.WithDedicatedMacKey>,
                SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<M,Nonce.Required>
        }
    }

    sealed interface WithoutNonce<out A : AuthType<out K>, K : KeyType> :
        SymmetricEncryptionAlgorithm<A, Nonce.Without, K> {
        sealed interface Unauthenticated :
            WithoutNonce<AuthType.Unauthenticated, KeyType.Integrated>,
            SymmetricEncryptionAlgorithm.Unauthenticated<Nonce.Without>

        sealed interface Authenticated<out A : AuthType.Authenticated<out K>, out K : KeyType> :
            SymmetricEncryptionAlgorithm.Authenticated<A, Nonce.Without, K> {
            interface Integrated :
                Authenticated<AuthType.Authenticated.Integrated, KeyType.Integrated>,
                WithoutNonce<AuthType.Authenticated.Integrated, KeyType.Integrated>,
                SymmetricEncryptionAlgorithm.Authenticated.Integrated<Nonce.Without>

            interface WithDedicatedMac<M : MAC> :
                Authenticated<AuthType.Authenticated.WithDedicatedMac<M, Nonce.Without>, KeyType.WithDedicatedMacKey>,
                WithoutNonce<AuthType.Authenticated.WithDedicatedMac<M, Nonce.Without>, KeyType.WithDedicatedMacKey>,
                SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<M, Nonce.Without>

        }
    }

    /**
     * Advanced Encryption Standard
     */
    sealed class AES<K : KeyType, A : AuthType<K>>(modeOfOps: ModeOfOperation, override val keySize: BitLength) :
        BlockCipher<A, Nonce.Required, K>(modeOfOps, blockSize = 128.bit),
        SymmetricEncryptionAlgorithm.RequiringNonce<A, K> {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated,
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
            ) :
                SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.WithDedicatedMac<at.asitplus.signum.indispensable.mac.HMAC>,
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
        SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated,
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


//Here come the contracts!

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipherAlias")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm<*, *, *>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<*, *, *>)
        returns(false) implies (this@isBlockCipher is StreamCipher<*, *, *>)
    }
    return this is BlockCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedAlias")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm<*, *, *>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<*, *, *>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<*>)
    }
    return this.authCapability is AuthType.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacAlias")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm<*, *, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, *>)
    }
    return this.authCapability is AuthType.Authenticated.WithDedicatedMac<*, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipher")
@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricEncryptionAlgorithm<A, I, K>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher<A, I, K>)
        returns(false) implies (this@isBlockCipher is StreamCipher<A, I, K>)
    }
    return this is BlockCipher<*, *, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticated")
@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType, I : Nonce> SymmetricEncryptionAlgorithm<A, I, K>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<A, I, K>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<I>)
    }
    return this.authCapability is AuthType.Authenticated<*>
}


/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMac")
@OptIn(ExperimentalContracts::class)
fun <I : Nonce> SymmetricEncryptionAlgorithm<*, I, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*, I>)
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
@JvmName("requiresNonce")
@OptIn(ExperimentalContracts::class)
fun <A : AuthType<K>, K : KeyType> SymmetricEncryptionAlgorithm<A, *, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce<A, K>)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegrated")
@OptIn(ExperimentalContracts::class)
fun < I : Nonce> SymmetricEncryptionAlgorithm.Authenticated<*, I, *>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.Integrated<I>)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*,I>)
    }
    return this.authCapability is AuthType.Authenticated.Integrated
}


//Second level A

//A-WITHOUTNONCE

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedWithout")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.WithoutNonce<*, *>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated<*, *>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.WithoutNonce.Unauthenticated)
    }
    return this.authCapability is AuthType.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacWithout")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.WithoutNonce<*, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.WithDedicatedMac<*>)
        returns(false) implies (
                (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.WithoutNonce.Unauthenticated
                        || this@hasDedicatedMac is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.Integrated))

    }
    return this.authCapability is AuthType.Authenticated.WithDedicatedMac<*, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegratedWithout")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated<*,*>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.Integrated)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.WithDedicatedMac<*>)
    }
    return this.authCapability is AuthType.Authenticated.Integrated
}


//A-NONCE

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedWith")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.RequiringNonce<*, *>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated<*, *>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.RequiringNonce.Unauthenticated)
    }
    return this.authCapability is AuthType.Authenticated<*>
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacWith")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.RequiringNonce<*, *>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.WithDedicatedMac<*>)
        returns(false) implies (
                (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.RequiringNonce.Unauthenticated
                || this@hasDedicatedMac is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated))

    }
    return this.authCapability is AuthType.Authenticated.WithDedicatedMac<*, *>
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegratedWith")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated<*,*>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.WithDedicatedMac<*>)
    }
    return this.authCapability is AuthType.Authenticated.Integrated
}


//Second Level B

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceUnauth")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.Unauthenticated<*>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce.Unauthenticated)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce.Unauthenticated)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAuth")
@OptIn(ExperimentalContracts::class)
fun <A : AuthType.Authenticated<K>, K : KeyType> SymmetricEncryptionAlgorithm.Authenticated<A, *, K>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated<A, K>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated<A, K>)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAuthAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm.Authenticated<*, *, *>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated<*, *>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated<*, *>)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAuthIntegrated")
@OptIn(ExperimentalContracts::class)
fun  SymmetricEncryptionAlgorithm.Authenticated.Integrated<*>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.Integrated)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.Integrated)
    }
    return this.nonce is Nonce.Required
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceWithDedicatedMac")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm.Authenticated.WithDedicatedMac<*,*>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce.Authenticated.WithDedicatedMac<*>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce.Authenticated.WithDedicatedMac<*>)
    }
    return this.nonce is Nonce.Required
}
