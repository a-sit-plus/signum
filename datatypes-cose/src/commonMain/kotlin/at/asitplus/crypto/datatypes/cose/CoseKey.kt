package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.failure
import at.asitplus.KmmResult.Companion.success
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.Signum
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import at.asitplus.crypto.datatypes.misc.compressY
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.CborLabel
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure

/**
 * COSE public key as per [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.html#page-33).  Since this is used as part of a COSE-specific DTO, every property is nullable
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseKeyUncompressedSerializer::class)
data class CoseKey(
    val type: CoseKeyType,
    val keyId: ByteArray? = null,
    val algorithm: CoseAlgorithm? = null,
    val operations: Array<CoseKeyOperation>? = null,
    val baseIv: ByteArray? = null,
    val keyParams: CoseKeyParams?,
) {
    override fun toString(): String {
        return "CoseKey(type=$type," +
                " keyId=${keyId?.encodeToString(Base16(strict = true))}," +
                " algorithm=$algorithm," +
                " operations=${operations?.contentToString()}," +
                " baseIv=${baseIv?.encodeToString(Base16(strict = true))}," +
                keyParams.toString()
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as CoseKey

        if (type != other.type) return false
        if (keyId != null) {
            if (other.keyId == null) return false
            if (!keyId.contentEquals(other.keyId)) return false
        } else if (other.keyId != null) return false
        if (algorithm != other.algorithm) return false
        if (operations != null) {
            if (other.operations == null) return false
            if (!operations.contentEquals(other.operations)) return false
        } else if (other.operations != null) return false
        if (baseIv != null) {
            if (other.baseIv == null) return false
            if (!baseIv.contentEquals(other.baseIv)) return false
        } else if (other.baseIv != null) return false
        if (keyParams != other.keyParams) return false

        return true
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + (keyId?.contentHashCode() ?: 0)
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (operations?.contentHashCode() ?: 0)
        result = 31 * result + (baseIv?.contentHashCode() ?: 0)
        result = 31 * result + keyParams.hashCode()
        return result
    }

    /**
     * @return a KmmResult wrapped [CryptoPublicKey] equivalent if conversion is possible (i.e. if all key params are set)
     * or the first error. More details in either [CoseKeyParams.RsaParams.toCryptoPublicKey] or [CoseKeyParams.EcYByteArrayParams.toCryptoPublicKey]
     */
    fun toCryptoPublicKey(): KmmResult<CryptoPublicKey> =
        keyParams?.toCryptoPublicKey() ?: failure(IllegalArgumentException("No public key parameters!"))

    fun serialize() = kotlin.runCatching { cborSerializer.encodeToByteArray(this) }.getOrElse {
        if (it is CoseKeyUncompressedSerializer.RetrydecodeEcException) cborSerializer.encodeToByteArray(
            CoseKeyCompressedSerializer,
            this
        ) else throw it
    }

    /**
     * Contains convenience functions
     */
    companion object {
        fun deserialize(it: ByteArray) =
            runCatching { cborSerializer.decodeFromByteArray(CoseKeyUncompressedSerializer, it) }.fold(onSuccess = {
                Result.success(it)
            }, onFailure = { ex ->
                if (ex is CoseKeyUncompressedSerializer.RetrydecodeEcException) kotlin.runCatching {
                    cborSerializer.decodeFromByteArray(CoseKeyCompressedSerializer, it)
                } else Result.failure(ex)
            }).wrap()

        fun fromKeyId(keyId: String): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromDid(keyId).toCoseKey().getOrThrow() }.wrap()

        /**
         * iOS encoded is currently only supporting uncompressed keys. Might change in the future
         */
        fun fromIosEncoded(bytes: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromIosEncoded(bytes).toCoseKey().getOrThrow() }.wrap()

        fun fromCoordinates(curve: CoseEllipticCurve, x: ByteArray, y: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.Ec(curve.toEcCurve(), x, y).toCoseKey().getOrThrow() }.wrap()
    }
}

/**
 * Converts [CryptoPublicKey] into a KmmResult wrapped [CoseKey]
 * If [algorithm] is not set then key can be used for any algorithm with same kty (RFC 8152), returns [IllegalArgumentException] for invalid kty/algorithm pairs
 */
fun CryptoPublicKey.toCoseKey(algorithm: CoseAlgorithm? = null, useCompression: Signum? = null): KmmResult<CoseKey> =
    when (this) {
        is CryptoPublicKey.Ec ->
            if ((algorithm != null) && (algorithm != when (curve) {
                    EcCurve.SECP_256_R_1 -> CoseAlgorithm.ES256
                    EcCurve.SECP_384_R_1 -> CoseAlgorithm.ES384
                    EcCurve.SECP_521_R_1 -> CoseAlgorithm.ES512
                })
            ) failure(IllegalArgumentException("Algorithm and Key Type mismatch"))
            else {
                /**
                 * if set use this, if not use receive value
                 */
                val compression = useCompression ?: this.yOnReceive
                val keyParams = if (compression) {
                    CoseKeyParams.EcYBoolParams(
                        curve = curve.toCoseCurve(),
                        x = x,
                        y = this.compressY()
                    )
                } else CoseKeyParams.EcYByteArrayParams(
                    curve = curve.toCoseCurve(),
                    x = x,
                    y = y
                )
                runCatching {
                    CoseKey(
                        keyParams = keyParams,
                        type = CoseKeyType.EC2,
                        keyId = didEncoded.encodeToByteArray(),
                        algorithm = algorithm
                    )
                }.wrap()
            }

        is CryptoPublicKey.Rsa ->
            if ((algorithm != null) && (algorithm !in listOf(
                    CoseAlgorithm.PS256, CoseAlgorithm.PS384, CoseAlgorithm.PS512,
                    CoseAlgorithm.RS256, CoseAlgorithm.RS384, CoseAlgorithm.RS512
                ))
            ) failure(IllegalArgumentException("Algorithm and Key Type mismatch"))
            else runCatching {
                CoseKey(
                    keyParams = CoseKeyParams.RsaParams(
                        n = n,
                        e = e.encodeToByteArray()
                    ),
                    type = CoseKeyType.RSA,
                    keyId = didEncoded.encodeToByteArray(),
                    algorithm = algorithm
                )
            }.wrap()
    }

private const val COSE_KID = "coseKid"
var CryptoPublicKey.coseKid: String
    get() = additionalProperties[COSE_KID] ?: didEncoded
    set(value) {
        additionalProperties[COSE_KID] = value
    }


@OptIn(ExperimentalSerializationApi::class)
object CoseKeyUncompressedSerializer : KSerializer<CoseKey> {

    @Serializable
    private class UncompressedCompoundCoseKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @CborLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("k")
        @ByteString
        val k: ByteArray? = null,
    ) {
        constructor(src: CoseKey) : this(
            src.type,
            src.keyId,
            src.algorithm,
            src.operations,
            src.baseIv,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.curve else null,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.x else null,
            when (src.keyParams) {
                is CoseKeyParams.EcYByteArrayParams -> src.keyParams.y
                is CoseKeyParams.EcYBoolParams -> throw RetrydecodeEcException()
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.n
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.e
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.SymmKeyParams -> params.k
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.d
                is CoseKeyParams.EcKeyParams<*> -> params.d
                else -> null
            },
        )
    }

    @Serializable
    private class CompressedCompoundCoseKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: Boolean? = null,
        @CborLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @CborLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("k")
        @ByteString
        val k: ByteArray? = null,
    ) {
        constructor(src: CoseKey) : this(
            src.type,
            src.keyId,
            src.algorithm,
            src.operations,
            src.baseIv,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.curve else null,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.x else null,
            when (src.keyParams) {
                is CoseKeyParams.EcYBoolParams -> src.keyParams.y
                is CoseKeyParams.EcYByteArrayParams -> throw IllegalArgumentException("this container does demands EC point compression")
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.n
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.e
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.SymmKeyParams -> params.k
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.d
                is CoseKeyParams.EcKeyParams<*> -> params.d
                else -> null
            },
        )
    }

    private interface SerialContainer {
        fun toCoseKey(): CoseKey
    }


    @Serializable
    private class CoseUncompressedEcKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.EC2) throw IllegalArgumentException("Not an EC key!")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.EcYByteArrayParams(curve, x, y, d))

    }

    @Serializable
    private class CoseCompressedEcKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: Boolean? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.EC2) throw IllegalArgumentException("Not an EC key!")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.EcYBoolParams(curve, x, y, d))

    }


    @Serializable
    private class CoseRsaKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @CborLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.RSA) throw IllegalArgumentException("Not an RSA key!")
        }

        override fun toCoseKey() = CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.RsaParams(n, e, d))
    }

    @Serializable
    private class CoseSymmKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("k")
        val k: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.SYMMETRIC) throw IllegalArgumentException("Not a symmetric key!")
            if (k == null) throw IllegalArgumentException("Parameter k not optional for symmetric keys")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.SymmKeyParams(k!!))

    }

    override val descriptor: SerialDescriptor
        get() = UncompressedCompoundCoseKeySerialContainer.serializer().descriptor

    override fun deserialize(decoder: Decoder): CoseKey {
        val labels = mapOf<String, Long>(
            "kty" to 1,
            "kid" to 2,
            "alg" to 3,
            "key_ops" to 4,
            "Base IV" to 5,
            "k/n/crv" to -1,
            "x/e" to -2,
            "y" to -3,
            "d" to 4
        )

        lateinit var type: CoseKeyType
        var keyId: ByteArray? = null
        var alg: CoseAlgorithm? = null
        var keyOps: Array<CoseKeyOperation>? = null
        var baseIv: ByteArray? = null
        var n: ByteArray? = null
        var crv: CoseEllipticCurve? = null
        var xOrE: ByteArray? = null
        var y: ByteArray? = null
        var d: ByteArray? = null
        var k: ByteArray? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == -1) break
                val label = descriptor.getElementAnnotations(index).filterIsInstance<CborLabel>().first().label
                when (label) {
                    labels["kty"] -> type =
                        decodeSerializableElement(CoseKeyTypeSerializer.descriptor, index, CoseKeyTypeSerializer)

                    labels["kid"] -> keyId =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["alg"] -> alg =
                        decodeNullableSerializableElement(
                            CoseAlgorithmSerializer.descriptor,
                            index,
                            CoseAlgorithmSerializer
                        )

                    labels["key_ops"] -> keyOps =
                        decodeNullableSerializableElement(
                            ArraySerializer(CoseKeyOperationSerializer).descriptor,
                            index,
                            ArraySerializer(CoseKeyOperationSerializer)
                        )

                    labels["k/n/crv"] -> {
                        when (type) {
                            CoseKeyType.EC2 -> {
                                val deser = CoseEllipticCurveSerializer
                                crv = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.RSA -> {
                                val deser = ByteArraySerializer()
                                n = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.SYMMETRIC -> {
                                val deser = ByteArraySerializer()
                                k = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }
                        }

                    }

                    labels["x/e"] -> xOrE =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["y"] -> y = kotlin.runCatching {
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )
                    }.getOrElse { throw RetrydecodeEcException() }

                    labels["d"] -> d =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    else -> {
                        break
                    }
                }
            }
        }
        return when (type) {
            CoseKeyType.EC2 -> {
                CoseUncompressedEcKeySerialContainer(type, keyId, alg, keyOps, baseIv, crv, xOrE, y, d).toCoseKey()
            }

            CoseKeyType.RSA -> {
                CoseRsaKeySerialContainer(type, keyId, alg, keyOps, baseIv, n, xOrE, d).toCoseKey()
            }

            CoseKeyType.SYMMETRIC -> {
                CoseSymmKeySerialContainer(type, keyId, alg, keyOps, baseIv, k).toCoseKey()
            }
        }
    }

    class RetrydecodeEcException : SerializationException()

    override fun serialize(encoder: Encoder, value: CoseKey) {
        encoder.encodeSerializableValue(
            UncompressedCompoundCoseKeySerialContainer.serializer(),
            UncompressedCompoundCoseKeySerialContainer(value)
        )
    }

}


@OptIn(ExperimentalSerializationApi::class)
object CoseKeyCompressedSerializer : KSerializer<CoseKey> {

    @Serializable
    private class CompressedCompoundCoseKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: Boolean? = null,
        @CborLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @CborLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("k")
        @ByteString
        val k: ByteArray? = null,
    ) {
        constructor(src: CoseKey) : this(
            src.type,
            src.keyId,
            src.algorithm,
            src.operations,
            src.baseIv,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.curve else null,
            if (src.keyParams is CoseKeyParams.EcKeyParams<*>) src.keyParams.x else null,
            when (src.keyParams) {
                is CoseKeyParams.EcYBoolParams -> src.keyParams.y
                is CoseKeyParams.EcYByteArrayParams -> throw IllegalArgumentException("this container does demands EC point compression")
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.n
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.e
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.SymmKeyParams -> params.k
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.d
                is CoseKeyParams.EcKeyParams<*> -> params.d
                else -> null
            },
        )
    }

    private interface SerialContainer {
        fun toCoseKey(): CoseKey
    }


    @Serializable
    private class CoseCompressedEcKeySerialContainer(
        @CborLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @CborLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @CborLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @CborLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @CborLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @CborLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @CborLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @CborLabel(-3)
        @SerialName("y")
        @ByteString
        val y: Boolean? = null,
        @CborLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null,
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.EC2) throw IllegalArgumentException("Not an EC key!")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.EcYBoolParams(curve, x, y, d))

    }


    override val descriptor: SerialDescriptor
        get() = CompressedCompoundCoseKeySerialContainer.serializer().descriptor

    override fun deserialize(decoder: Decoder): CoseKey {
        val labels = mapOf<String, Long>(
            "kty" to 1,
            "kid" to 2,
            "alg" to 3,
            "key_ops" to 4,
            "Base IV" to 5,
            "k/n/crv" to -1,
            "x/e" to -2,
            "y" to -3,
            "d" to 4
        )

        lateinit var type: CoseKeyType
        var keyId: ByteArray? = null
        var alg: CoseAlgorithm? = null
        var keyOps: Array<CoseKeyOperation>? = null
        var baseIv: ByteArray? = null
        var n: ByteArray? = null
        var crv: CoseEllipticCurve? = null
        var xOrE: ByteArray? = null
        var y: Boolean? = null
        var d: ByteArray? = null
        var k: ByteArray? = null

        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == -1) break
                val label = descriptor.getElementAnnotations(index).filterIsInstance<CborLabel>().first().label
                when (label) {
                    labels["kty"] -> type =
                        decodeSerializableElement(CoseKeyTypeSerializer.descriptor, index, CoseKeyTypeSerializer)

                    labels["kid"] -> keyId =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["alg"] -> alg =
                        decodeNullableSerializableElement(
                            CoseAlgorithmSerializer.descriptor,
                            index,
                            CoseAlgorithmSerializer
                        )

                    labels["key_ops"] -> keyOps =
                        decodeNullableSerializableElement(
                            ArraySerializer(CoseKeyOperationSerializer).descriptor,
                            index,
                            ArraySerializer(CoseKeyOperationSerializer)
                        )

                    labels["k/n/crv"] -> {
                        when (type) {
                            CoseKeyType.EC2 -> {
                                val deser = CoseEllipticCurveSerializer
                                crv = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.RSA -> {
                                val deser = ByteArraySerializer()
                                n = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.SYMMETRIC -> {
                                val deser = ByteArraySerializer()
                                k = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }
                        }

                    }

                    labels["x/e"] -> xOrE =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    labels["y"] -> y =
                        decodeNullableSerializableElement(
                            Boolean.serializer().descriptor,
                            index,
                            Boolean.serializer()
                        )

                    labels["d"] -> d =
                        decodeNullableSerializableElement(
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
                        )

                    else -> {
                        break
                    }
                }
            }
        }
        return when (type) {
            CoseKeyType.EC2 -> {
                CoseCompressedEcKeySerialContainer(type, keyId, alg, keyOps, baseIv, crv, xOrE, y, d).toCoseKey()
            }

            else -> throw SerializationException("Only point-compressed EC keys are supported here!")
        }
    }


    override fun serialize(encoder: Encoder, value: CoseKey) {
        encoder.encodeSerializableValue(
            CompressedCompoundCoseKeySerialContainer.serializer(),
            CompressedCompoundCoseKeySerialContainer(value)
        )
    }

}