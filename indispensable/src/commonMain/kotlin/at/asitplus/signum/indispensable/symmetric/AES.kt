package at.asitplus.signum.indispensable.symmetric

import at.asitplus.awesn1.KnownOIDs
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.aes128_CBC
import at.asitplus.awesn1.aes128_ECB
import at.asitplus.awesn1.aes128_GCM
import at.asitplus.awesn1.aes128_wrap
import at.asitplus.awesn1.aes192_CBC
import at.asitplus.awesn1.aes192_ECB
import at.asitplus.awesn1.aes192_GCM
import at.asitplus.awesn1.aes192_wrap
import at.asitplus.awesn1.aes256_CBC
import at.asitplus.awesn1.aes256_ECB
import at.asitplus.awesn1.aes256_GCM
import at.asitplus.awesn1.aes256_wrap
import at.asitplus.signum.Enumeration
import at.asitplus.signum.HazardousMaterials
import at.asitplus.signum.indispensable.Digest
import at.asitplus.signum.indispensable.HmacAlgorithm
import at.asitplus.signum.indispensable.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.internals.ImplementationError

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


class AesGcmAlgorithm internal constructor(keySize: BitLength) :
    SymmetricEncryptionAlgorithm.Authenticated.Integrated<NonceTrait.Required>,
    SymmetricEncryptionAlgorithm.RequiringNonce<AuthCapability.Authenticated.Integrated, KeyType.Integrated>,
    AES<NonceTrait.Required, KeyType.Integrated, AuthCapability.Authenticated.Integrated>(
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
    AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(
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
    AES<NonceTrait.Without, KeyType.Integrated, AuthCapability.Unauthenticated>(
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
    AES<NonceTrait.Required, K, A>(
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