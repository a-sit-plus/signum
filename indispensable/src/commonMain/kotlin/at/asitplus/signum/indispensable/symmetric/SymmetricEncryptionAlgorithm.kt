package at.asitplus.signum.indispensable.symmetric

import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.encodeTo8Bytes
import at.asitplus.signum.indispensable.HMAC
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
sealed interface SymmetricEncryptionAlgorithm<out A : AuthCapability<*>, out I : NonceTrait<*>> :
    Identifiable {
    val authCapability: A

    /** Indicates if this algorithm requires a nonce.*/
    val nonceTrait: I

    override fun toString(): String

    companion object {

        val entries by lazy {
            listOf(ChaCha20Poly1305) + AES_128.entries + AES_192.entries + AES_256.entries
        }

        //ChaCha20Poly1305 is already an object, so we don't need to redeclare here

        val AES_128 = AESDefinition(128.bit)
        val AES_192 = AESDefinition(192.bit)
        val AES_256 = AESDefinition(256.bit)

        /**
         * AES configuration hierarchy
         */
        class AESDefinition(val keySize: BitLength) {

            @OptIn(HazardousMaterials::class)
            val entries by lazy {
                listOf(GCM, ECB) + CBC.entries + WRAP.entries
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
             * AES in Electronic Codebook Mode. You almost certainly don't want to use this
             */
            @HazardousMaterials("ECB is almost always insecure!")
            val ECB = AES.ECB(keySize)

            /**
             * AES Key Wrapping as per [RFC 3394](https://www.rfc-editor.org/rfc/rfc3394)
             */
            val WRAP = WrapDefinition(keySize)

            class WrapDefinition(keySize: BitLength) {
                val entries by lazy { listOf(RFC3394) }
                val RFC3394 = AES.WRAP.RFC3394(keySize)
            }

            class CbcDefinition(keySize: BitLength) {
                @OptIn(HazardousMaterials::class)
                val entries by lazy { listOf(PLAIN) + HMAC.entries }
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
                class HmacDefinition(innerCipher: AES.CBC.Unauthenticated) {
                    @OptIn(HazardousMaterials::class)
                    val entries by lazy { listOf(SHA_256, SHA_384, SHA_512, SHA_1) }
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
    sealed class AES<I : NonceTrait<*>, A : AuthCapability<*>>(
        modeOfOps: ModeOfOperation,
        override val keySize: BitLength
    ) :
        BlockCipher<A, I>(modeOfOps, blockSize = 128.bit),
        SymmetricEncryptionAlgorithm<A, I> {
        override val name: String = "AES-${keySize.bits} ${modeOfOps.acronym}"

        override fun toString(): String = name

        class GCM internal constructor(keySize: BitLength) :
            AES<NonceTrait.Required, AuthCapability.AuthenticatedIntegrated>(
                ModeOfOperation.GCM,
                keySize
            ) {
            override val authCapability = AuthCapability.authenticatedIntegrated
            override val nonceTrait = NonceTrait.required
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_GCM
                192u -> KnownOIDs.aes192_GCM
                256u -> KnownOIDs.aes256_GCM
                else -> throw ImplementationError("AES GCM OID")
            }
        }

        sealed class WRAP(keySize: BitLength) :
            AES<NonceTrait.Without, AuthCapability.Unauthenticated>(ModeOfOperation.ECB, keySize) {

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
            AES<NonceTrait.Without, AuthCapability.Unauthenticated>(ModeOfOperation.ECB, keySize) {
            override val authCapability = AuthCapability.unauthenticated
            override val nonceTrait = NonceTrait.without
            override val oid: ObjectIdentifier = when (keySize.bits) {
                128u -> KnownOIDs.aes128_ECB
                192u -> KnownOIDs.aes192_ECB
                256u -> KnownOIDs.aes256_ECB
                else -> throw ImplementationError("AES ECB OID")
            }
        }

        sealed class CBC<A : AuthCapability<*>>(keySize: BitLength) :
            AES<NonceTrait.Required, A>(ModeOfOperation.CBC, keySize) {
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
                val innerCipher: Unauthenticated,
                val mac: at.asitplus.signum.indispensable.HMAC,
                val macInputCalculation: MacInputCalculation,
                val macAuthTagTransform: MacAuthTagTransformation,
                val authTagSize: BitLength
            ) : RequiringNonce<AuthCapability.WithDedicatedMac>,
                CBC<AuthCapability.WithDedicatedMac>(
                    innerCipher.keySize
                ) {
                constructor(innerCipher: Unauthenticated, mac: at.asitplus.signum.indispensable.HMAC) : this(
                    innerCipher,
                    mac,
                    DefaultMacInputCalculation,
                    DefaultMacAuthTagTransformation,
                    authTagSize = BitLength(mac.outputLength.bits / 2u)
                )

                override val name = super.name + " $mac"
                val preferredMacKeyLength: BitLength get() = innerCipher.keySize

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
    object ChaCha20Poly1305 : StreamCipher<AuthCapability.AuthenticatedIntegrated, NonceTrait.Required>() {
        override val name: String = "ChaCha20-Poly1305"
        override fun toString() = name
        override val keySize = 256u.bit
        override val oid = KnownOIDs.chaCha20Poly1305
        override val authCapability = AuthCapability.authenticatedIntegrated
        override val nonceTrait = NonceTrait.required
    }
}

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.Authenticated<*>.authTagSize: BitLength get() = when(this) {
    is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> authTagSize
    is SymmetricEncryptionAlgorithm.AES.GCM -> blockSize
    SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> 128u.bit
    is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated -> absurd()
    is SymmetricEncryptionAlgorithm.AES.ECB -> absurd()
    is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> absurd()
}

@Suppress("UNCHECKED_CAST")
@OptIn(HazardousMaterials::class)
val <I : NonceTrait<*>> SymmetricEncryptionAlgorithm.EncryptThenMAC<I>.innerCipher: SymmetricEncryptionAlgorithm.Unauthenticated<I>
    get() = when(this) {
        is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> innerCipher as SymmetricEncryptionAlgorithm.Unauthenticated<I>
        is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated, is SymmetricEncryptionAlgorithm.AES.ECB,
        is SymmetricEncryptionAlgorithm.AES.GCM, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394,
        is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> absurd()
    }

/**
 * The mac function used to provide authenticated encryption
 */
@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.mac: HMAC get() = when (this) {
    is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> mac
    is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated, is SymmetricEncryptionAlgorithm.AES.ECB,
    is SymmetricEncryptionAlgorithm.AES.GCM, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394,
    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> absurd()
}

/**
 * The preferred length pf the MAC key. Can be overridden during key generation and is unconstrained.
 */
@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.preferredMacKeyLength: BitLength get() = when (this) {
    is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> preferredMacKeyLength
    is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated, is SymmetricEncryptionAlgorithm.AES.ECB,
    is SymmetricEncryptionAlgorithm.AES.GCM, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394,
    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> absurd()
}

/**
 * Specifies how the inputs to the MAC are to be encoded/processed
 */
@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.macInputCalculation: MacInputCalculation get() = when (this) {
    is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> macInputCalculation
    is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated, is SymmetricEncryptionAlgorithm.AES.ECB,
    is SymmetricEncryptionAlgorithm.AES.GCM, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394,
    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> absurd()
}

/**
 * Specifies how the inputs to the MAC are to be encoded/processed
 */
@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.macAuthTagTransform: MacAuthTagTransformation get() = when (this) {
    is SymmetricEncryptionAlgorithm.AES.CBC.HMAC -> macAuthTagTransform
    is SymmetricEncryptionAlgorithm.AES.CBC.Unauthenticated, is SymmetricEncryptionAlgorithm.AES.ECB,
    is SymmetricEncryptionAlgorithm.AES.GCM, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394,
    is SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> absurd()
}

@OptIn(HazardousMaterials::class)
val SymmetricEncryptionAlgorithm.RequiringNonce<*>.nonceSize: BitLength get() = when(this) {
    is SymmetricEncryptionAlgorithm.AES.CBC -> 128u.bit
    is SymmetricEncryptionAlgorithm.AES.GCM -> 96.bit
    SymmetricEncryptionAlgorithm.ChaCha20Poly1305 -> 96u.bit
    is SymmetricEncryptionAlgorithm.AES.ECB, is SymmetricEncryptionAlgorithm.AES.WRAP.RFC3394 -> absurdNonce()
}

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
    fun SymmetricEncryptionAlgorithm.EncryptThenMAC<*>.(ciphertext: ByteArray, iv: ByteArray, aad: ByteArray): ByteArray =
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
sealed class BlockCipher<A : AuthCapability<*>, I : NonceTrait<*>>(
    val mode: ModeOfOperation,
    val blockSize: BitLength
) : SymmetricEncryptionAlgorithm<A, I> {

    enum class ModeOfOperation(val friendlyName: String, val acronym: String) {
        GCM("Galois Counter Mode", "GCM"),
        CBC("Cipher Block Chaining Mode", "CBC"),
        ECB("Electronic Codebook Mode", "ECB"),
    }
}

/**
 * Marker interface indicating a block cipher. Purely informational
 */
sealed class StreamCipher<A : AuthCapability<*>, I : NonceTrait<*>> : SymmetricEncryptionAlgorithm<A, I>


//Here come the contracts!

/**Use to smart-cast this algorithm*/
@JvmName("isBlockCipherAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *>.isBlockCipher(): Boolean {
    contract {
        returns(true) implies (this@isBlockCipher is BlockCipher)
        returns(false) implies (this@isBlockCipher is StreamCipher)
    }
    return this is BlockCipher
}

/**Use to smart-cast this algorithm*/
@JvmName("isStreamCipherAlias")
@OptIn(ExperimentalContracts::class)
fun SymmetricEncryptionAlgorithm<*, *>.isStreamCipher(): Boolean {
    contract {
        returns(true) implies (this@isStreamCipher is StreamCipher)
        returns(false) implies (this@isStreamCipher is BlockCipher)
    }
    return this is StreamCipher
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
