package at.asitplus.signum.supreme.asymmetric

import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.KeyAgreementPrivateValue
import at.asitplus.signum.indispensable.KeyAgreementPublicValue
import at.asitplus.signum.indispensable.kdf.HKDF
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bytes
import at.asitplus.signum.indispensable.nativeDigest
import at.asitplus.signum.indispensable.symmetric.AuthCapability
import at.asitplus.signum.indispensable.symmetric.KeyType
import at.asitplus.signum.indispensable.symmetric.NonceTrait
import at.asitplus.signum.indispensable.symmetric.SymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.symmetric.authTag
import at.asitplus.signum.indispensable.symmetric.authTagSize
import at.asitplus.signum.indispensable.symmetric.from
import at.asitplus.signum.indispensable.symmetric.keyFrom
import at.asitplus.signum.indispensable.symmetric.nonceSize
import at.asitplus.signum.indispensable.symmetric.sealedBox
import at.asitplus.signum.internals.xor
import at.asitplus.signum.supreme.agree.Ephemeral
import at.asitplus.signum.supreme.agree.keyAgreement
import at.asitplus.signum.supreme.kdf.expandStep
import at.asitplus.signum.supreme.kdf.extractStep
import at.asitplus.signum.supreme.symmetric.Encryptor
import at.asitplus.signum.supreme.symmetric.decrypt
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import kotlinx.coroutines.runBlocking
import kotlin.experimental.and

/** I2OSP (Integer To Octet String Primitive) for case len = 1 only */
@Suppress("NOTHING_TO_INLINE")
private inline fun i2ospForLen1(value: Byte): ByteArray = byteArrayOf(value)

/** I2OSP (Integer To Octet String Primitive) for case len = 1 only */
@Suppress("NOTHING_TO_INLINE")
private inline fun i2ospForLen1(value: Int): ByteArray {
    require (value in 0..0xff)
    return i2ospForLen1((value and 0xff).toByte())
}

/** I2OSP (Integer To Octet String Primitive) for case len = 2 only */
@Suppress("NOTHING_TO_INLINE")
private inline fun i2ospForLen2(value: Int): ByteArray {
    require(value in 0..0xffff)
    return byteArrayOf(((value shr 8) and 0xff).toByte(), (value and 0xff).toByte())
}

private inline fun os2ip(value: ByteArray): BigInteger = BigInteger.fromByteArray(value, Sign.POSITIVE)

private fun concat(vararg datas: ByteArray): ByteArray {
    val totalSize = datas.sumOf { it.size }
    val result = ByteArray(totalSize)
    datas.fold(0, { offset, data ->
        data.copyInto(result, destinationOffset = offset)
        return@fold offset+data.size
    })
    return result
}

private interface SuiteKDFContext {
    val kdf: HPKE.KDF
    /** RFC 9180 suite_id */
    val suiteId: ByteArray
}

/** RFC 9180 HPKE */
class HPKE<SecretKey,PublicKey>(val kem: KEM<PublicKey,SecretKey>, override val kdf: KDF, val aead: AEAD): SuiteKDFContext {

    data class KeyPair<SecretKey, PublicKey>(
        /** secret key */
        val sk: SecretKey,
        /** public key */
        val pk: PublicKey)

    data class EncapResult(
        /** symmetric key (RFC 9180: shared_secret) */
        val sharedSecret: ByteArray,
        /** encapsulated key (RFC 9180: enc) */
        val encapsulatedSecret: ByteArray)

    data class SenderSetupResult(
        /** encapsulated key (RFC 9180: enc) */
        val encapsulatedSecret: ByteArray,
        /** sending context */
        val context: HPKE.Context.S
    )

    data class SealOneShotResult(
        /** encapsulated key (RFC 9180: enc) */
        val encapsulatedSecret: ByteArray,
        /** ciphertext (RFC 9180: ct) */
        val ciphertext: ByteArray
    )

    data class ExportOneShotSenderResult(
        /** encapsulated key (RFC 9180: enc) */
        val encapsulatedSecret: ByteArray,
        /** exported shared secret */
        val exported: ByteArray
    )


    class MessageLimitReachedError: Throwable()

    interface KDF {
        /** RFC 9180 kdf_id */
        val kdfId: Int

        /**
         * The output size of the [Extract] function in bytes.
         */
        val Nh: BitLength

        /**
         * Extract a pseudorandom key of fixed length [Nh] bytes from input keying material [ikm]
         * and an optional byte string [salt].
         */
        suspend fun Extract(salt: ByteArray?, ikm: ByteArray): ByteArray

        /**
         * Expand a pseudorandom key [prk] using optional string [info] into [L] bytes of output keying material.
         */
        suspend fun Expand(prk: ByteArray, info: ByteArray, L: BitLength): ByteArray

        companion object {
            /** bridges from HPKE KDF definition to signum's HKDF definition */
            private data class SignumHKDFProxy(override val kdfId: Int, private val hkdf: HKDF) : HPKE.KDF {
                override val Nh: BitLength
                    get() = BitLength.fromBytes(hkdf.outputLength)

                override suspend fun Expand(prk: ByteArray, info: ByteArray, L: BitLength) =
                    hkdf.expandStep(prk, info, L).getOrThrow()

                override suspend fun Extract(salt: ByteArray?, ikm: ByteArray) =
                    hkdf.extractStep(salt, ikm).getOrThrow()
            }

            /** well-known KDFs as referenced in RFC9180 section 7.2 */
            val HKDF_SHA256: HPKE.KDF = SignumHKDFProxy(kdfId = 0x0001, hkdf = HKDF.SHA256)
            val HKDF_SHA384: HPKE.KDF = SignumHKDFProxy(kdfId = 0x0002, hkdf = HKDF.SHA384)
            val HKDF_SHA512: HPKE.KDF = SignumHKDFProxy(kdfId = 0x0003, hkdf = HKDF.SHA512)
        }
    }
    interface KEM<PublicKey, SecretKey> {
        /** RFC 9180 kem_id */
        val kemId: Int
        /**
         * The length in bytes of a KEM shared secret produced by this KEM.
         */
        val Nsecret: BitLength

        /**
         * The length in bytes of an encapsulated key produced by this KEM.
         */
        val Nenc: BitLength

        /**
         * The length in bytes of an encoded public key for this KEM.
         */
        val Npk: BitLength

        /**
         * Randomized algorithm to generate a key pair (skX, pkX).
         */
        suspend fun GenerateKeyPair(): KeyPair<SecretKey, PublicKey>

        /**
         * Deterministic algorithm to derive a key pair (skX, pkX) from the byte string [ikm],
         * where ikm SHOULD have at least Nsk bytes of entropy.
         */
        suspend fun DeriveKeyPair(ikm: ByteArray): KeyPair<SecretKey, PublicKey>

        /**
         * Produce a byte string of length [Npk] encoding the public key [pkX].
         */
        fun SerializePublicKey(pkX: PublicKey): ByteArray

        /**
         * Parse a byte string of length [Npk] to recover a public key. This function can raise a DeserializeError
         * error upon [pkXm] deserialization failure.
         */
        fun DeserializePublicKey(pkXm: ByteArray): PublicKey

        /**
         * Randomized algorithm to generate an ephemeral, fixed-length symmetric key (the KEM shared secret)
         * and a fixed-length encapsulation of that key that can be decapsulated by the holder of the private
         * key corresponding to pkR. This function can raise an EncapError on encapsulation failure.
         */
        suspend fun Encap(pkR: PublicKey, ikm: ByteArray? = null): EncapResult

        /**
         * Deterministic algorithm using the private key [skR] to recover the ephemeral symmetric key (the KEM
         * shared secret) from its encapsulated representation [enc]. This function can raise a DecapError on
         * decapsulation failure.
         */
        suspend fun Decap(enc: ByteArray, skR: SecretKey): ByteArray

        interface WithAuthEncapDecap<PublicKey, SecretKey> : KEM<PublicKey, SecretKey> {
            /**
             * Same as [Encap](), and the outputs encode an assurance that the KEM shared secret was generated
             * by the holder of the private key skS.
             */
            suspend fun AuthEncap(pkR: PublicKey, skS: SecretKey, ikm: ByteArray? = null): EncapResult
            /**
             * Same as [Decap](), and the recipient is assured that the KEM shared secret was generated by the
             * holder of the private key skS.
             */
            suspend fun AuthDecap(enc: ByteArray, skR: SecretKey, pkS: PublicKey): ByteArray
        }
        interface WithSerializablePrivateKey<PublicKey, SecretKey> : KEM<PublicKey, SecretKey> {
            /**
             * The length in bytes of an encoded private key for this KEM.
             */
            val Nsk: BitLength
            /**
             * Produce a byte string of length [Nsk] encoding the private key [skX].
             */
            fun SerializePrivateKey(skX: SecretKey): ByteArray
            /**
             * Parse a byte string of length [Nsk] to recover a private key.
             * This function can raise a DeserializeError error upon [skXm] deserialization failure.
             */
            fun DeserializePrivateKey(skXm: ByteArray): SecretKey
        }

        companion object {
            /** well-known KEMs as specified in RFC9180 section 7.1 */
            val DHKEM_P256_HKDF_SHA256 = DHKEM(0x0010, KDF.HKDF_SHA256, ECCurve.SECP_256_R_1)
            val DHKEM_P384_HKDF_SHA384 = DHKEM(0x0011, KDF.HKDF_SHA384, ECCurve.SECP_384_R_1)
            val DHKEM_P521_HKDF_SHA512 = DHKEM(0x0012, KDF.HKDF_SHA512, ECCurve.SECP_521_R_1)
            val DHKEM_X25519_HKDF_SHA256: DHKEM get() = throw UnsupportedCryptoException("X.25519 is unsupported for now")
            val DHKEM_X448_HKDF_SHA512: DHKEM get() = throw UnsupportedCryptoException("X.448 is unsupported for now")
        }
    }
    interface AEAD {
        /** RFC 9180 aead_id */
        val aeadId: Int
        /**
         * The length in bytes of a key for this algorithm.
         */
        val Nk: BitLength

        /**
         * The length in bytes of a nonce for this algorithm.
         */
        val Nn: BitLength

        /**
         * The length in bytes of the authentication tag for this algorithm.
         */
        val Nt: BitLength

        /**
         * Encrypt and authenticate plaintext [pt] with associated data aad using symmetric key [key] and nonce [nonce],
         * yielding ciphertext and tag `ct`. This function can raise a [MessageLimitReachedError] upon failure.
         */
        suspend fun Seal(key: ByteArray, nonce: ByteArray, aad: ByteArray?, pt: ByteArray): ByteArray
        /**
         * Decrypt ciphertext and tag [ct] using associated data [aad] with symmetric key [key] and nonce [nonce],
         * returning plaintext message `pt`. This function can raise an OpenError or [MessageLimitReachedError] upon
         * failure.
         */
        suspend fun Open(key: ByteArray, nonce: ByteArray, aad: ByteArray?, ct: ByteArray): ByteArray

        companion object {

            /** well-known AEADs as specified in RFC9180 section 7.3 */
            private data class SignumAEADProxy(
                override val aeadId: Int,
                private val alg: SymmetricEncryptionAlgorithm<
                        AuthCapability.Authenticated.Integrated,
                        NonceTrait.Required,
                        KeyType.Integrated>
            ) : HPKE.AEAD {
                override val Nk get() = alg.keySize
                override val Nn get() = alg.nonceSize
                override val Nt get() = alg.authTagSize

                override suspend fun Seal(key: ByteArray, nonce: ByteArray, aad: ByteArray?, pt: ByteArray): ByteArray {
                    val box =  Encryptor(alg, key, null, nonce, aad).encrypt(pt)
                    //val box = runBlocking { alg.keyFrom(key).getOrThrow().encrypt(pt, aad).getOrThrow() }
                    return box.encryptedData + box.authTag
                }

                override suspend fun Open(key: ByteArray, nonce: ByteArray, aad: ByteArray?, ct: ByteArray): ByteArray {
                    require(ct.size >= Nt.bytes.toInt())
                    val ciphertext = ct.copyOfRange(0, ct.size - Nt.bytes.toInt())
                    val tag = ct.copyOfRange(ct.size - Nt.bytes.toInt(), ct.size)
                    val box = alg.sealedBox.withNonce(nonce).from(ciphertext, tag).getOrThrow()
                    return box.decrypt(alg.keyFrom(key).getOrThrow(), aad ?: byteArrayOf()).getOrThrow()
                }
            }
            val AES_128_GCM: AEAD = SignumAEADProxy(0x0001, SymmetricEncryptionAlgorithm.AES_128.GCM)
            val AES_256_GCM: AEAD = SignumAEADProxy(0x0002, SymmetricEncryptionAlgorithm.AES_256.GCM)
            val CHACHA20POLY1305: AEAD = SignumAEADProxy(0x0003, SymmetricEncryptionAlgorithm.ChaCha20Poly1305)
            val EXPORT_ONLY = object : AEAD {
                override val aeadId get() = 0xFFFF
                private val NOPE: Nothing get() = throw UnsupportedOperationException("EXPORT_ONLY AEAD may only be used for secret export")
                override val Nt get() = 0.bytes
                override val Nk get() = 0.bytes
                override val Nn get() = 0.bytes
                override suspend fun Open(key: ByteArray, nonce: ByteArray, aad: ByteArray?, ct: ByteArray) = NOPE
                override suspend fun Seal(key: ByteArray, nonce: ByteArray, aad: ByteArray?, pt: ByteArray) = NOPE
            }
        }
    }

    companion object {
        private suspend fun SuiteKDFContext.LabeledExtract(salt: ByteArray?, label: ByteArray, ikm: ByteArray): ByteArray {
            val labeled_ikm = concat("HPKE-v1".encodeToByteArray(), suiteId, label, ikm)
            return kdf.Extract(salt, labeled_ikm)
        }

        private suspend fun SuiteKDFContext.LabeledExpand(prk: ByteArray, label: ByteArray, info: ByteArray, L: BitLength): ByteArray {
            val labeled_info = concat(i2ospForLen2(L.bytes.toInt()), "HPKE-v1".encodeToByteArray(),
                suiteId, label,info)
            return kdf.Expand(prk, labeled_info, L)
        }
    }

    data class DHKEM(override val kemId: Int, override val kdf: HPKE.KDF, private val dhGroup: ECCurve) :
        KEM<KeyAgreementPublicValue.ECDH, KeyAgreementPrivateValue.ECDH>,
        KEM.WithAuthEncapDecap<KeyAgreementPublicValue.ECDH, KeyAgreementPrivateValue.ECDH>,
        KEM.WithSerializablePrivateKey<KeyAgreementPublicValue.ECDH, KeyAgreementPrivateValue.ECDH>,
        SuiteKDFContext
    {
        override val suiteId = concat("KEM".encodeToByteArray(), i2ospForLen2(kemId))
        private suspend fun DH(sk: KeyAgreementPrivateValue.ECDH, pk: KeyAgreementPublicValue.ECDH) =
              sk.keyAgreement(pk).getOrThrow()

        override val Nsecret get() = dhGroup.nativeDigest.outputLength
        override val Nenc get() = Npk
        // encoding length uncompressed
        override val Npk get() = dhGroup.coordinateLength + dhGroup.coordinateLength + 1.bytes
        override val Nsk get() = dhGroup.scalarLength

        override suspend fun GenerateKeyPair(): KeyPair<KeyAgreementPrivateValue.ECDH, KeyAgreementPublicValue.ECDH> {
            // ECDH.Ephemeral is suspend; bridge it the same way DH() does just above (runBlocking),
            // rather than rippling `suspend` through the entire sender-side KEM/Seal public API.
            val it =  KeyAgreementPrivateValue.ECDH.Ephemeral(curve = dhGroup).getOrThrow()
            return KeyPair(it, it.publicValue)
        }

        override suspend fun DeriveKeyPair(ikm: ByteArray): KeyPair<KeyAgreementPrivateValue.ECDH, KeyAgreementPublicValue.ECDH> {
            val dkp_prk = LabeledExtract(byteArrayOf(), "dkp_prk".encodeToByteArray(), ikm)
            var sk = BigInteger.ZERO
            var counter = 0
            while (sk.isZero() || sk >= dhGroup.order) {
                if (counter > 255) throw RuntimeException("DeriveKeyPairError")
                val bytes = LabeledExpand(dkp_prk, "candidate".encodeToByteArray(), i2ospForLen1(counter), dhGroup.scalarLength)
                if (dhGroup == ECCurve.SECP_521_R_1) bytes[0] = bytes[0] and 0x01.toByte()
                sk = os2ip(bytes)
                counter += 1
            }
            val key = CryptoPrivateKey.EC.WithPublicKey(sk, dhGroup, true, true)
            return KeyPair(key, key.publicValue)
        }

        override fun SerializePublicKey(pkX: KeyAgreementPublicValue.ECDH) = pkX.asCryptoPublicKey().toAnsiX963Encoded(useCompressed = false)
        override fun DeserializePublicKey(pkXm: ByteArray): KeyAgreementPublicValue.ECDH = CryptoPublicKey.EC.fromAnsiX963Bytes(dhGroup, pkXm)
        override fun SerializePrivateKey(skX: KeyAgreementPrivateValue.ECDH) = (skX as CryptoPrivateKey.EC.WithPublicKey).privateKeyBytes
        override fun DeserializePrivateKey(skXm: ByteArray): KeyAgreementPrivateValue.ECDH = CryptoPrivateKey.EC.WithPublicKey(BigInteger.fromByteArray(skXm, Sign.POSITIVE), dhGroup, true, true)

        private suspend fun ExtractAndExpand(dh: ByteArray, kem_context: ByteArray): ByteArray {
            val eae_prk = LabeledExtract(byteArrayOf(), "eae_prk".encodeToByteArray(), dh)
            val shared_secret = LabeledExpand(eae_prk, "shared_secret".encodeToByteArray(), kem_context, Nsecret)
            return shared_secret
        }

        override suspend fun Encap(pkR: KeyAgreementPublicValue.ECDH, ikm: ByteArray?): EncapResult {
            val (skE, pkE) = if(ikm!=null) DeriveKeyPair(ikm)else  GenerateKeyPair()
            val dh = DH(skE, pkR)
            val enc = SerializePublicKey(pkE)
            val pkRm = SerializePublicKey(pkR)
            val kem_context = concat(enc, pkRm)
            val shared_secret = ExtractAndExpand(dh, kem_context)
            return EncapResult(shared_secret, enc)
        }

        override suspend fun Decap(enc: ByteArray, skR: KeyAgreementPrivateValue.ECDH): ByteArray {
            val pkE = DeserializePublicKey(enc)
            val dh = DH(skR, pkE)
            val pkRm = SerializePublicKey(skR.publicValue)
            val kem_context = concat(enc, pkRm)
            val shared_secret = ExtractAndExpand(dh, kem_context)
            return shared_secret
        }

        override suspend fun AuthEncap(
            pkR: KeyAgreementPublicValue.ECDH,
            skS: KeyAgreementPrivateValue.ECDH,
            ikm: ByteArray?
        ): EncapResult {
            val (skE, pkE) = if (ikm != null) DeriveKeyPair(ikm) else GenerateKeyPair()
            val dh = concat(DH(skE, pkR), DH(skS, pkR))
            val enc = SerializePublicKey(pkE)
            val pkRm = SerializePublicKey(pkR)
            val pkSm = SerializePublicKey(skS.publicValue)
            val kem_context = concat(enc, pkRm, pkSm)
            val shared_secret = ExtractAndExpand(dh, kem_context)
            return EncapResult(shared_secret, enc)
        }

        override suspend fun AuthDecap(
            enc: ByteArray,
            skR: KeyAgreementPrivateValue.ECDH,
            pkS: KeyAgreementPublicValue.ECDH
        ): ByteArray {
            val pkE = DeserializePublicKey(enc)
            val dh = concat(DH(skR, pkE), DH(skR, pkS))
            val pkRm = SerializePublicKey(skR.publicValue)
            val pkSm = SerializePublicKey(pkS)
            val kem_context  = concat(enc, pkRm, pkSm)
            val shared_secret = ExtractAndExpand(dh, kem_context)
            return shared_secret
        }
    }

    override val suiteId = concat(
        "HPKE".encodeToByteArray(), i2ospForLen2(kem.kemId),
        i2ospForLen2(kdf.kdfId), i2ospForLen2(aead.aeadId))

    enum class Mode(
        /** RFC 9180: mode_id */
        val modeId: Byte)
    {
        /** Unauthenticated sender, no pre-shared secret (RFC 9180: mode_base) */
        BASE(0x00),
        /** Authentication using a pre-shared secret (RFC 9180: mode_psk) */
        PSK(0x01),
        /** Sender authentication using a KEM keypair (RFC 9180: mode_auth) */
        AUTH(0x02),
        /** Authentication using both pre-shared secret and KEM keypair (RFC 9180: mode_auth_psk) */
        AUTH_PSK(0x03);

        val mode get() = byteArrayOf(modeId)
    }

    private interface ContextSharedInterface {
        suspend fun Export(exporter_context: ByteArray, L: BitLength): ByteArray
    }

    class Context internal constructor(
        private val suite: HPKE<*, *>,
        private val key: ByteArray,
        private val base_nonce: ByteArray,
        private val exporter_secret: ByteArray,
    ) : ContextSharedInterface {
        private val seq = ByteArray(suite.aead.Nn.bytes.toInt()) { 0 }

        fun ComputeNonce() = this.base_nonce xor this.seq
        private fun IncrementSeq() {
            this.seq.indices.reversed().forEach { i ->
                val v = seq[i].toUByte()
                if (v != 0xff.toUByte()) {
                    seq[i] = (v+1u).toByte()
                    return@IncrementSeq
                }
                seq[i] = 0x00
            }
            throw MessageLimitReachedError()
        }

        override suspend fun Export(exporter_context: ByteArray, L: BitLength): ByteArray {
            return suite.LabeledExpand(exporter_secret, "sec".encodeToByteArray(), exporter_context, L)
        }
        /** Sender-side context */
        inner class S: ContextSharedInterface by this@Context {
            suspend fun Seal(aad: ByteArray, pt: ByteArray): ByteArray {
                val ct = suite.aead.Seal(key, ComputeNonce(), aad, pt)
                IncrementSeq()
                return ct
            }
        }
        /** Receiver-side context */
        inner class R: ContextSharedInterface by this@Context {
            suspend fun Open(aad: ByteArray, ct: ByteArray): ByteArray {
                val pt = suite.aead.Open(key, ComputeNonce(), aad, ct)
                IncrementSeq()
                return pt
            }
        }
    }

    /**
     * Suspending faux-constructor for [Context] (public API: `hpke.Context(mode, …)`). Runs the RFC
     * 9180 key schedule (VerifyPSKInputs + the suspending `LabeledExtract`/`LabeledExpand`) against
     * this suite, then hands the fully-derived key material to [Context]'s private constructor.
     * A member function rather than an `init` block, because the key schedule is suspending.
     */
    suspend fun Context(
        mode: Mode,
        shared_secret: ByteArray,
        info: ByteArray,
        psk: ByteArray,
        psk_id: ByteArray,
    ): Context {
        /** RFC9180 VerifyPSKInputs */
        require(psk.isEmpty() == psk_id.isEmpty()) { "Inconsistent PSK inputs" }
        when (mode) {
            Mode.BASE, Mode.AUTH -> require(psk.isEmpty()) { "PSK provided when not needed" }
            /** In the PSK and AuthPSK modes, the PSK MUST have at least 32 bytes of entropy */
            Mode.PSK, Mode.AUTH_PSK -> require(psk.size >= 32) { "The PSK MUST have at least 32 bytes of entropy" }
        }
        val psk_id_hash = LabeledExtract(byteArrayOf(), "psk_id_hash".encodeToByteArray(), psk_id)
        val info_hash = LabeledExtract(byteArrayOf(), "info_hash".encodeToByteArray(), info)
        val key_schedule_context = concat(mode.mode, psk_id_hash, info_hash)
        val secret = LabeledExtract(shared_secret, "secret".encodeToByteArray(), psk)
        val key = LabeledExpand(secret, "key".encodeToByteArray(), key_schedule_context, aead.Nk)
        val base_nonce = LabeledExpand(secret, "base_nonce".encodeToByteArray(), key_schedule_context, aead.Nn)
        val exporter_secret = LabeledExpand(secret, "exp".encodeToByteArray(), key_schedule_context, kdf.Nh)
        return Context(this, key, base_nonce, exporter_secret)
    }

    suspend fun SetupBaseS(pkR: PublicKey, info: ByteArray): SenderSetupResult {
        val (shared_secret, enc) = kem.Encap(pkR)
        return SenderSetupResult(enc, Context(Mode.BASE, shared_secret, info, byteArrayOf(), byteArrayOf()).S())
    }

    suspend fun SetupBaseR(enc: ByteArray, skR: SecretKey, info: ByteArray): Context.R {
        val shared_secret = kem.Decap(enc, skR)
        return Context(Mode.BASE, shared_secret, info, byteArrayOf(), byteArrayOf()).R()
    }

    suspend fun SetupPSKS(pkR: PublicKey, info: ByteArray, psk: ByteArray, psk_id: ByteArray): SenderSetupResult {
        val (shared_secret, enc) = kem.Encap(pkR)
        return SenderSetupResult(enc, Context(Mode.PSK, shared_secret, info, psk, psk_id).S())
    }

    suspend fun SetupPSKR(enc: ByteArray, skR: SecretKey, info: ByteArray, psk: ByteArray, psk_id: ByteArray): Context.R {
        val shared_secret = kem.Decap(enc, skR)
        return Context(Mode.PSK, shared_secret, info, psk, psk_id).R()
    }

    suspend fun SetupAuthS(pkR: PublicKey, info: ByteArray, skS: SecretKey): SenderSetupResult {
        require(kem is KEM.WithAuthEncapDecap) { "Authenticated encapsulation is not supported by $kem" }
        val (shared_secret, enc) = kem.AuthEncap(pkR, skS)
        return SenderSetupResult(enc, Context(Mode.AUTH, shared_secret, info, byteArrayOf(), byteArrayOf()).S())
    }

    suspend fun SetupAuthR(enc: ByteArray, skR: SecretKey, info: ByteArray, pkS: PublicKey): Context.R {
        require(kem is KEM.WithAuthEncapDecap) { "Authenticated encapsulation is not supported by $kem" }
        val shared_secret = kem.AuthDecap(enc, skR, pkS)
        return Context(Mode.AUTH, shared_secret, info, byteArrayOf(), byteArrayOf()).R()
    }

    suspend fun SetupAuthPSKS(pkR: PublicKey, info: ByteArray, psk: ByteArray, psk_id: ByteArray, skS: SecretKey): SenderSetupResult {
        require(kem is KEM.WithAuthEncapDecap) { "Authenticated encapsulation is not supported by $kem" }
        val (shared_secret, enc) = kem.AuthEncap(pkR, skS)
        return SenderSetupResult(enc, Context(Mode.AUTH_PSK, shared_secret, info, psk, psk_id).S())
    }

    suspend fun SetupAuthPSKR(enc: ByteArray, skR: SecretKey, info: ByteArray, psk: ByteArray, psk_id: ByteArray, pkS: PublicKey): Context.R {
        require(kem is KEM.WithAuthEncapDecap) { "Authenticated encapsulation is not supported by $kem" }
        val shared_secret = kem.AuthDecap(enc, skR, pkS)
        return Context(Mode.AUTH_PSK, shared_secret, info, psk, psk_id).R()
    }

    suspend fun SealBase(pkR: PublicKey, info: ByteArray, aad: ByteArray, pt: ByteArray): SealOneShotResult {
        val (enc, ctx) = SetupBaseS(pkR, info)
        val ct = ctx.Seal(aad, pt)
        return SealOneShotResult(enc, ct)
    }

    suspend fun SealPSK(pkR: PublicKey, info: ByteArray, aad: ByteArray, pt: ByteArray, psk: ByteArray, psk_id: ByteArray): SealOneShotResult {
        val (enc, ctx) = SetupPSKS(pkR, info, psk, psk_id)
        val ct = ctx.Seal(aad, pt)
        return SealOneShotResult(enc, ct)
    }

    suspend fun SealAuth(pkR: PublicKey, info: ByteArray, aad: ByteArray, pt: ByteArray, skS: SecretKey): SealOneShotResult {
        val (enc, ctx) = SetupAuthS(pkR, info, skS)
        val ct = ctx.Seal(aad, pt)
        return SealOneShotResult(enc, ct)
    }

    suspend fun SealAuthPSK(pkR: PublicKey, info: ByteArray, aad: ByteArray, pt: ByteArray, psk: ByteArray, psk_id: ByteArray, skS: SecretKey): SealOneShotResult {
        val (enc, ctx) = SetupAuthPSKS(pkR, info, psk, psk_id, skS)
        val ct = ctx.Seal(aad, pt)
        return SealOneShotResult(enc, ct)
    }

    suspend fun OpenBase(enc: ByteArray, skR: SecretKey, info: ByteArray, aad: ByteArray, ct: ByteArray): ByteArray {
        val ctx = SetupBaseR(enc, skR, info)
        return ctx.Open(aad, ct)
    }

    suspend  fun OpenPSK(enc: ByteArray, skR: SecretKey, info: ByteArray, aad: ByteArray, ct: ByteArray, psk: ByteArray, psk_id: ByteArray): ByteArray {
        val ctx = SetupPSKR(enc, skR, info, psk, psk_id)
        return ctx.Open(aad, ct)
    }

    suspend fun OpenAuth(enc: ByteArray, skR: SecretKey, info: ByteArray, aad: ByteArray, ct: ByteArray, pkS: PublicKey): ByteArray {
        val ctx = SetupAuthR(enc, skR, info, pkS)
        return ctx.Open(aad, ct)
    }

    suspend  fun OpenAuthPSK(enc: ByteArray, skR: SecretKey, info: ByteArray, aad: ByteArray, ct: ByteArray, psk: ByteArray, psk_id: ByteArray, pkS: PublicKey): ByteArray {
        val ctx = SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)
        return ctx.Open(aad, ct)
    }

    suspend  fun SendExportBase(pkR: PublicKey, info: ByteArray, exporter_context: ByteArray, L: BitLength): ExportOneShotSenderResult {
        val (enc, ctx) = SetupBaseS(pkR, info)
        val exported = ctx.Export(exporter_context, L)
        return ExportOneShotSenderResult(enc, exported)
    }

    suspend  fun SendExportPSK(pkR: PublicKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, psk: ByteArray, psk_id: ByteArray): ExportOneShotSenderResult {
        val (enc, ctx) = SetupPSKS(pkR, info, psk, psk_id)
        val exported = ctx.Export(exporter_context, L)
        return ExportOneShotSenderResult(enc, exported)
    }

    suspend  fun SendExportAuth(pkR: PublicKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, skS: SecretKey): ExportOneShotSenderResult {
        val (enc, ctx) = SetupAuthS(pkR, info, skS)
        val exported = ctx.Export(exporter_context, L)
        return ExportOneShotSenderResult(enc, exported)
    }

    suspend fun SendExportAuthPSK(pkR: PublicKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, psk: ByteArray, psk_id: ByteArray, skS: SecretKey): ExportOneShotSenderResult {
        val (enc, ctx) = SetupAuthPSKS(pkR, info, psk, psk_id, skS)
        val exported = ctx.Export(exporter_context, L)
        return ExportOneShotSenderResult(enc, exported)
    }

    suspend fun ReceiveExportBase(enc: ByteArray, skR: SecretKey, info: ByteArray, exporter_context: ByteArray, L: BitLength): ByteArray {
        val ctx = SetupBaseR(enc, skR, info)
        return ctx.Export(exporter_context, L)
    }

    suspend  fun ReceiveExportPSK(enc: ByteArray, skR: SecretKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, psk: ByteArray, psk_id: ByteArray): ByteArray {
        val ctx = SetupPSKR(enc, skR, info, psk, psk_id)
        return ctx.Export(exporter_context, L)
    }

    suspend  fun ReceiveExportAuth(enc: ByteArray, skR: SecretKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, pkS: PublicKey): ByteArray {
        val ctx = SetupAuthR(enc, skR, info, pkS)
        return ctx.Export(exporter_context, L)
    }

    suspend fun ReceiveExportAuthPSK(enc: ByteArray, skR: SecretKey, info: ByteArray, exporter_context: ByteArray, L: BitLength, psk: ByteArray, psk_id: ByteArray, pkS: PublicKey): ByteArray {
        val ctx = SetupAuthPSKR(enc, skR, info, psk, psk_id, pkS)
        return ctx.Export(exporter_context, L)
    }

}