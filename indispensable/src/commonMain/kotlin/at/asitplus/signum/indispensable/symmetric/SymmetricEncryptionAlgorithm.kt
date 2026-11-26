@file:Suppress("INFERRED_TYPE_VARIABLE_INTO_POSSIBLE_EMPTY_INTERSECTION")
package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.internals.ImplementationError
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.contract
import kotlin.jvm.JvmName

/**
 * Base interface for every symmetric encryption algorithm. A Symmetric encryption algorithm is characterised by:
 * * an [authCapability] ([AuthCapability.Unauthenticated], [AuthCapability.AuthenticatedIntegrated], [AuthCapability.WithDedicatedMac]
 * * its [nonceTrait] ([NonceTrait.Required], [NonceTrait.Without])
 * * the [keySize]
 * * its [name]
 */
interface SymmetricEncryptionAlgorithm<out A : AuthCapability<*>, out I : NonceTrait<*>> :
    Identifiable, Enumerable {
    val authCapability: A

    /** Length of the nonce for algorithms that require one. */
    val requiredNonceSize: BitLength? get() = null

    /** Length of the authentication tag for authenticated algorithms. */
    val authenticationTagSize: BitLength? get() = null

    /** Indicates if this algorithm requires a nonce.*/
    val nonceTrait: I

    override fun toString(): String

    companion object : Enumeration<SymmetricEncryptionAlgorithm<*, *>> {

        override val entries: List<SymmetricEncryptionAlgorithm<*, *>> by lazy {
            listOf(ChaCha20Poly1305) + AES_128.entries + AES_192.entries + AES_256.entries
        }

        //ChaCha20Poly1305 is already an object, so we don't need to redeclare here

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) : Enumeration<AES<*, *>> {

            @OptIn(HazardousMaterials::class)
            override val entries by lazy {
                listOf(GCM, ECB, ECB_NOPADDING) + CBC.entries + WRAP.entries
            }

            /**
             * AES in Galois Counter Mode
             */
            val GCM = AES.GCM(keySize)

            /**
             * AES in Cipher Block Chaining Mode
             */
            val CBC = CbcDefinition(keySize)

            /**
             * AES in Electronic Codebook Mode with PKCS7 padding. You almost certainly don't want to use this
             */
            @HazardousMaterials("ECB is almost always insecure!")
            val ECB = AES.ECB(keySize)

            /**
             * AES in Electronic Codebook Mode without padding. You almost certainly don't want to use this
             */
            @HazardousMaterials("ECB is almost always insecure!")
            val ECB_NOPADDING = AES.ECB_NOPADDING(keySize)

            /**
             * AES Key Wrapping as per [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)
             */
            val WRAP = WrapDefinition(keySize)

            class WrapDefinition(keySize: BitLength) : Enumeration<AES.WRAP> {
                override val entries: List<AES.WRAP> by lazy { listOf(RFC3394) }
                val RFC3394 = AES.WRAP.RFC3394(keySize)
            }

            class CbcDefinition(keySize: BitLength) : Enumeration<AES.CBC<*>> {
                @OptIn(HazardousMaterials::class)
                override val entries: List<AES.CBC<*>> by lazy { listOf(PLAIN) + HMAC.entries }

                /**
                 * Plain, Unauthenticated AES in Cipher Block Chaining mode.
                 * You almost certainly don't want to use this as is, but rather some [HMAC]-authenticated variant
                 */
                @HazardousMaterials("Unauthenticated!")
                val PLAIN = AES.CBC.Unauthenticated(keySize)

                /**
                 * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                 */
                @OptIn(HazardousMaterials::class)
                val HMAC = HmacDefinition(PLAIN)

                /**
                 * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                 */
                class HmacDefinition(innerCipher: AES.CBC.Unauthenticated) :
                    Enumeration<AES.CBC.HMAC> {
                    @OptIn(HazardousMaterials::class)
                    override val entries: List<AES.CBC.HMAC> by lazy { listOf(SHA_256, SHA_384, SHA_512, SHA_1) }

                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_256 = AES.CBC.HMAC(innerCipher, HMAC.SHA256)

                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_384 = AES.CBC.HMAC(innerCipher, HMAC.SHA384)

                    /**
                     * AES-CBC-HMAC as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1)
                     */
                    val SHA_512 = AES.CBC.HMAC(innerCipher, HMAC.SHA512)

                    @HazardousMaterials("Insecure hash function!")
                    val SHA_1 = AES.CBC.HMAC(innerCipher, HMAC.SHA1)
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

    typealias Integrated<I> = SymmetricEncryptionAlgorithm<AuthCapability.Integrated, I>
    typealias Unauthenticated<I> = SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, I>
    typealias Authenticated<I> = SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, I>
    typealias AuthenticatedIntegrated<I> = SymmetricEncryptionAlgorithm<AuthCapability.AuthenticatedIntegrated, I>
    typealias EncryptThenMAC<I> = SymmetricEncryptionAlgorithm<AuthCapability.WithDedicatedMac, I>
    typealias RequiringNonce<A> = SymmetricEncryptionAlgorithm<A, NonceTrait.Required>
    typealias WithoutNonce<A> = SymmetricEncryptionAlgorithm<A, NonceTrait.Without>
    typealias AuthenticatedWithoutNonce = SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Without>
    typealias AuthenticatedRequiringNonce = SymmetricEncryptionAlgorithm<AuthCapability.Authenticated, NonceTrait.Required>
    typealias UnauthenticatedWithoutNonce = SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Without>
    typealias UnauthenticatedRequiringNonce = SymmetricEncryptionAlgorithm<AuthCapability.Unauthenticated, NonceTrait.Required>

    /**
     * Advanced Encryption Standard
     */
    abstract class AES<I : NonceTrait<*>, A : AuthCapability<*>>(
        modeOfOps: BlockCipher.ModeOfOperation,
        override val keySize: BitLength
    ) : SymmetricEncryptionAlgorithm<A, I>, BlockCipher<A, I> {
        override val mode: BlockCipher.ModeOfOperation = modeOfOps
        override val blockSize: BitLength = AES.blockSize
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        companion object : Enumeration<AES<*, *>> {
            val blockSize = 128.bit

            override val entries: List<AES<*, *>> by lazy {
                SymmetricEncryptionAlgorithm.AES_128.entries +
                    SymmetricEncryptionAlgorithm.AES_192.entries +
                    SymmetricEncryptionAlgorithm.AES_256.entries
            }
        }


        class GCM internal constructor(keySize: BitLength) :
            AES<NonceTrait.Required, AuthCapability.AuthenticatedIntegrated>(
                BlockCipher.ModeOfOperation.GCM,
                keySize
            ) {
            override val authCapability = AuthCapability.authenticatedIntegrated
            override val nonceTrait = NonceTrait.required
            override val requiredNonceSize = 96u.bit
            override val authenticationTagSize = blockSize
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw ImplementationError("AES GCM OID")
            }
        }

        abstract class WRAP(keySize: BitLength) :
            AES<NonceTrait.Without, AuthCapability.Unauthenticated>(BlockCipher.ModeOfOperation.ECB, keySize) {

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
                override val nonceTrait = NonceTrait.without
                override val authCapability = AuthCapability.unauthenticated
            }
            //on request, add RFC 5649  key wrapping here. requires manual work, though
        }

        @HazardousMaterials("ECB is almost always insecure!")
        class ECB internal constructor(keySize: BitLength) :
            AES<NonceTrait.Without, AuthCapability.Unauthenticated>(BlockCipher.ModeOfOperation.ECB, keySize) {
            override val authCapability = AuthCapability.unauthenticated
            override val nonceTrait = NonceTrait.without
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw ImplementationError("AES ECB OID")
            }
        }

        @HazardousMaterials("ECB is almost always insecure!")
        class ECB_NOPADDING(keySize: BitLength) :
            AES<NonceTrait.Without, AuthCapability.Unauthenticated>(BlockCipher.ModeOfOperation.ECB, keySize) {
            override val authCapability = AuthCapability.unauthenticated
            override val nonceTrait = NonceTrait.without
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw ImplementationError("AES ECB OID")
            }
        }

        abstract class CBC<A : AuthCapability<*>>(keySize: BitLength) :
            AES<NonceTrait.Required, A>(BlockCipher.ModeOfOperation.CBC, keySize) {
            override val requiredNonceSize: BitLength = 128u.bit
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_CBC
                192u -> KnownOIDs.aes192_CBC
                256u -> KnownOIDs.aes256_CBC
                else -> throw ImplementationError("AES CBC OID")
            }

            class Unauthenticated internal constructor(
                keySize: BitLength
            ) : CBC<AuthCapability.Unauthenticated>(keySize) {
                override val authCapability = AuthCapability.unauthenticated
                override val nonceTrait = NonceTrait.required
                override val name = super.name + " Plain"
            }

            /**
             * AEAD-capabilities bolted onto AES-CBC
             */
            class HMAC
            private constructor(
                override val innerCipher: Unauthenticated,
                override val mac: at.asitplus.signum.indispensable.mac.HMAC,
                override val macInputCalculation: MacInputCalculation,
                override val macAuthTagTransform: MacAuthTagTransformation,
                override val authenticationTagSize: BitLength
            ) : RequiringNonce<AuthCapability.WithDedicatedMac>,
                SymmetricEncryptionAlgorithmEncryptThenMac<NonceTrait.Required>,
                CBC<AuthCapability.WithDedicatedMac>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: at.asitplus.signum.indispensable.mac.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultMacInputCalculation,
                    DefaultMacAuthTagTransformation,
                    BitLength(mac.outputLength.bits / 2u)
                )

                override val name = super.name + " $mac"
                override val preferredMacKeyLength: BitLength get() = innerCipher.keySize
                val authTagSize: BitLength get() = authenticationTagSize

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
                ) = HMAC(
                    innerCipher,
                    mac,
                    dedicatedMacInputCalculation,
                    dedicatedMacAuthTagTransformation,
                    tagLength
                )

                override val authCapability = AuthCapability.withDedicatedMac
                override val nonceTrait = NonceTrait.required
            }
        }
    }

    /**
     * ChaCha20 with Poly-1305 AEAD stream cipher
     */
    object ChaCha20Poly1305 : StreamCipher<AuthCapability.AuthenticatedIntegrated, NonceTrait.Required> {
        override val name: String = "ChaCha20-Poly1305"
        override fun toString() = name
        override val keySize = 256u.bit
        override val oid = KnownOIDs.chaCha20Poly1305
        override val authCapability = AuthCapability.authenticatedIntegrated
        override val nonceTrait = NonceTrait.required
        override val requiredNonceSize = 96u.bit
        override val authenticationTagSize = 128u.bit
    }
}

interface SymmetricEncryptionAlgorithmEncryptThenMac<I: NonceTrait<*>>: SymmetricEncryptionAlgorithm.EncryptThenMAC<I> {
    val innerCipher: SymmetricEncryptionAlgorithm.Unauthenticated<I>
    val mac: MessageAuthenticationCode
    val preferredMacKeyLength: BitLength
    val macInputCalculation: MacInputCalculation
    val macAuthTagTransform: MacAuthTagTransformation
}

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.Authenticated<*>.authTagSize: BitLength
    get() = authenticationTagSize ?: throw IllegalStateException("Authenticated algorithms must provide their tag size")

val <I : NonceTrait<*>> SymmetricEncryptionAlgorithm.EncryptThenMAC<I>.innerCipher: SymmetricEncryptionAlgorithm.Unauthenticated<I>
    get() = (this as? SymmetricEncryptionAlgorithmEncryptThenMac<I>)?.innerCipher
        ?: throw IllegalStateException("Encrypt-then-MAC algorithm must provide its inner cipher")

/**
 * The mac function used to provide authenticated encryption
 */
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.mac: MessageAuthenticationCode
    get() = (this as? SymmetricEncryptionAlgorithmEncryptThenMac<*>)?.mac
        ?: throw IllegalStateException("Encrypt-then-MAC algorithm must provide its MAC")

/**
 * The preferred length pf the MAC key. Can be overridden during key generation and is unconstrained.
 */
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.preferredMacKeyLength: BitLength
    get() = (this as? SymmetricEncryptionAlgorithmEncryptThenMac<*>)?.preferredMacKeyLength
        ?: throw IllegalStateException("Encrypt-then-MAC algorithm must provide its preferred MAC key length")

/**
 * Specifies how the inputs to the MAC are to be encoded/processed
 */
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.macInputCalculation: MacInputCalculation
    get() = (this as? SymmetricEncryptionAlgorithmEncryptThenMac<*>)?.macInputCalculation
        ?: throw IllegalStateException("Encrypt-then-MAC algorithm must provide its MAC input calculation")

/**
 * Specifies how the inputs to the MAC are to be encoded/processed
 */
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.macAuthTagTransform: MacAuthTagTransformation
    get() = (this as? SymmetricEncryptionAlgorithmEncryptThenMac<*>)?.macAuthTagTransform
        ?: throw IllegalStateException("Encrypt-then-MAC algorithm must provide its tag transformation")

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.RequiringNonce<*>.nonceSize: BitLength
    get() = requiredNonceSize ?: throw IllegalStateException("Nonce-requiring algorithms must provide their nonce size")

class Box<out A: Unit?>(val a: A)

/**
 * Defines whether a cipher is authenticated or not
 */
class AuthCapability<out A: Box<*>?> private constructor(val a: A) {
    typealias Integrated = AuthCapability<Box<Nothing?>?>
    /**
     * Indicates an authenticated cipher
     */
    typealias Authenticated = AuthCapability<Box<*>>

    /**
     * An authenticated cipher construction that is inherently authenticated and thus permits no dedicated MAC key
     */
    typealias AuthenticatedIntegrated = AuthCapability<Box<Nothing?>>

    /**
     * An _Encrypt-then-MAC_ authenticated cipher construction based on an unauthenticated cipher with a dedicated MAC function, requiring a dedicated MAC key.
     */
    typealias WithDedicatedMac = AuthCapability<Box<Unit>>

    /**
     * Indicates an unauthenticated cipher
     */
    typealias Unauthenticated = AuthCapability<Nothing?>
    companion object {
        val authenticatedIntegrated: AuthenticatedIntegrated = AuthCapability(Box(null))
        val withDedicatedMac: WithDedicatedMac = AuthCapability(Box(Unit))
        val unauthenticated: Unauthenticated = AuthCapability(null)
    }
}

fun SymmetricEncryptionAlgorithm<AuthCapability<Box<Nothing>>, *>.absurd(): Nothing = authCapability.a.a

/**
 * Typealias defining the signature of the lambda for processing the MAC output into an auth tag.
 */
typealias MacAuthTagTransformation = SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.(macOutput: ByteArray) -> ByteArray


/**
 * The default dedicated mac output transform as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1),
 * taking the first [authTagSize] many bytes of the MAC output as auth tag.
 */
val DefaultMacAuthTagTransformation: MacAuthTagTransformation =
    fun SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.(
        macOutput: ByteArray
    ): ByteArray = macOutput.take(this.authTagSize.bytes.toInt()).toByteArray()

/**
 * Typealias defining the signature of the lambda for defining a custom MAC input calculation scheme.
 */
typealias MacInputCalculation = SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.(ciphertext: ByteArray, nonce: ByteArray, aad: ByteArray) -> ByteArray

/**
 * The default dedicated mac input calculation as per [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1), authenticating all inputs:
 * `AAD || IV || Ciphertext || AAD Length`, where AAD_length is a 64 bit big-endian representation of the aad length in bits
 */
val DefaultMacInputCalculation: MacInputCalculation =
    fun SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.(
        ciphertext: ByteArray,
        iv: ByteArray,
        aad: ByteArray
    ): ByteArray =
        aad + iv + ciphertext + (aad.size.toLong() * 8L).encodeTo8Bytes()

/**
 * Marker, indicating whether a symmetric encryption algorithms requires or prohibits the use of a nonce/IV
 */
class NonceTrait<out U: Unit?> private constructor(val a: U) {
    typealias Required = NonceTrait<Unit>
    typealias Without = NonceTrait<Nothing?>
    companion object {
        val required: Required = NonceTrait(Unit)
        val without: Without = NonceTrait(null)
    }
}

internal fun SymmetricEncryptionAlgorithm<*, NonceTrait<Nothing>>.absurdNonce(): Nothing = nonceTrait.a

/**
 * Marker interface indicating a block cipher. Purely informational
 */
interface BlockCipher<A : AuthCapability<*>, I : NonceTrait<*>> : SymmetricEncryptionAlgorithm<A, I> {
    val mode: ModeOfOperation
    val blockSize: BitLength

    interface ModeOfOperation {
        val name: String get() = acronym
        val ordinal: Int get() = entries.indexOfFirst { it === this }
        val friendlyName: String
        val acronym: String
        companion object {
            val GCM: ModeOfOperation = BuiltInMode("Galois Counter Mode", "GCM")
            val CBC: ModeOfOperation = BuiltInMode("Cipher Block Chaining Mode", "CBC")
            val ECB: ModeOfOperation = BuiltInMode("Electronic Codebook Mode", "ECB")
            @JvmStatic
            val entries: List<ModeOfOperation> get() = listOf(GCM, CBC, ECB)
            @JvmStatic
            fun values(): Array<ModeOfOperation> = entries.toTypedArray()
            @JvmStatic
            fun valueOf(name: String): ModeOfOperation = entries.firstOrNull { it.name == name }
                ?: throw IllegalArgumentException("No enum constant BlockCipher.ModeOfOperation.$name")
        }
    }
}

private data class BuiltInMode(
    override val friendlyName: String,
    override val acronym: String
) : BlockCipher.ModeOfOperation {
    override fun toString(): String = name
}

/**
 * Marker interface indicating a block cipher. Purely informational
 */
interface StreamCipher<A : AuthCapability<*>, I : NonceTrait<*>> : SymmetricEncryptionAlgorithm<A, I>


//Here come the contracts!

/** Whether this algorithm is a block cipher. Algorithms may be neither block nor stream ciphers. */
@get:JvmName("isBlockCipherProperty")
val SymmetricEncryptionAlgorithm<*, *>.isBlockCipher: Boolean get() = this is BlockCipher<*, *>

/** Whether this algorithm is a stream cipher. Algorithms may be neither block nor stream ciphers. */
@get:JvmName("isStreamCipherProperty")
val SymmetricEncryptionAlgorithm<*, *>.isStreamCipher: Boolean get() = this is StreamCipher<*, *>

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipherAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher)
    }
    return isBlockCipher
}

/**Use to smart-cast this algorithm*/
@JvmName("isStreamCipherAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *>.isStreamCipher(): Boolean {
    contract {
        returns(true) implies (this@isStreamCipher is StreamCipher)
    }
    return isStreamCipher
}

/**Use to smart-cast this algorithm*/
@JvmName("isAuthenticatedAlias")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait<*>> SymmetricEncryptionAlgorithm<*, I>.isAuthenticated(): Boolean {
    contract {
        returns(true) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Authenticated<I>)
        returns(false) implies (this@isAuthenticated is SymmetricEncryptionAlgorithm.Unauthenticated<I>)
    }
    return authCapability == AuthCapability.authenticatedIntegrated || authCapability == AuthCapability.withDedicatedMac
}

/**Use to smart-cast this algorithm*/
@JvmName("hasDedicatedMacAlias")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait<*>> SymmetricEncryptionAlgorithm<*, I>.hasDedicatedMac(): Boolean {
    contract {
        returns(true) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.EncryptThenMAC<I>)
        returns(false) implies (this@hasDedicatedMac is SymmetricEncryptionAlgorithm.Integrated<I>)
    }
    return authCapability == AuthCapability.withDedicatedMac
}

/**Use to smart-cast this algorithm*/
@JvmName("requiresNonceAlias")
@OptIn(ExperimentalContracts::class)
fun <A : AuthCapability<*>> SymmetricEncryptionAlgorithm<A, *>.requiresNonce(): Boolean {
    contract {
        returns(true) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.RequiringNonce<A>)
        returns(false) implies (this@requiresNonce is SymmetricEncryptionAlgorithm.WithoutNonce<A>)
    }
    return nonceTrait == NonceTrait.required
}

/**Use to smart-cast this algorithm*/
@JvmName("isIntegrated")
@OptIn(ExperimentalContracts::class)
fun <I : NonceTrait<*>> SymmetricEncryptionAlgorithm.Authenticated<I>.isIntegrated(): Boolean {
    contract {
        returns(true) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.AuthenticatedIntegrated<I>)
        returns(false) implies (this@isIntegrated is SymmetricEncryptionAlgorithm.EncryptThenMAC<I>)
    }
    return authCapability == AuthCapability.authenticatedIntegrated
}

interface SpecializedSymmetricEncryptionAlgorithm {
    val algorithm: SymmetricEncryptionAlgorithm<*, *>
}
