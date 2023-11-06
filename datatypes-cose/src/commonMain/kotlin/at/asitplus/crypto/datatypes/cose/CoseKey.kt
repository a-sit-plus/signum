package at.asitplus.crypto.datatypes.cose

import at.asitplus.KmmResult
import at.asitplus.KmmResult.Companion.wrap
import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.EcCurve
import at.asitplus.crypto.datatypes.asn1.encodeToByteArray
import at.asitplus.crypto.datatypes.cose.io.cborSerializer
import io.matthewnelson.encoding.base16.Base16
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.*
import kotlinx.serialization.builtins.ArraySerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.SerialLabel
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.encoding.decodeStructure

/**
 * COSE public key as per [RFC 8152](https://www.rfc-editor.org/rfc/rfc8152.html#page-33).  Since this is used as part of a COSE-specific DTO, every property is nullable
 */
@OptIn(ExperimentalSerializationApi::class)
@Serializable(with = CoseKeySerializer::class)
data class CoseKey(
    val type: CoseKeyType,
    val keyId: ByteArray? = null,
    val algorithm: CoseAlgorithm? = null,
    val operations: Array<CoseKeyOperation>? = null,
    val baseIv: ByteArray? = null,
    val keyParams: CoseKeyParams?
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
     * @return a KmmResult wrapped [CryptoPublicKey] equivalent if conversion is possible (i.e. if all key params are set)<br> or KmmResult.Failure in case the required key params are not contained in this COSE key (i.e. if only a `kid` is used)
     */
    fun toCryptoPublicKey(): KmmResult<CryptoPublicKey> =
        keyParams?.toCryptoPublicKey() ?: KmmResult.failure(IllegalArgumentException("No public key parameters!"))

    fun serialize() = cborSerializer.encodeToByteArray(this)

    companion object {
        fun deserialize(it: ByteArray) =
            runCatching { cborSerializer.decodeFromByteArray<CoseKey>(it) }.wrap()

        fun fromKeyId(keyId: String): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromKeyId(keyId).toCoseKey() }.wrap()

        fun fromIosEncoded(bytes: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.fromIosEncoded(bytes).toCoseKey() }.wrap()

        fun fromCoordinates(curve: CoseEllipticCurve, x: ByteArray, y: ByteArray): KmmResult<CoseKey> =
            runCatching { CryptoPublicKey.Ec.fromCoordinates(curve.toJwkCurve(), x, y).toCoseKey() }.wrap()

        @Deprecated("Use [fromIosEncoded] instead!")
        fun fromAnsiX963Bytes(type: CoseKeyType, curve: CoseEllipticCurve, it: ByteArray) =
            if (type == CoseKeyType.EC2 && curve == CoseEllipticCurve.P256) {
                val pubKey = CryptoPublicKey.Ec.fromAnsiX963Bytes(it)
                pubKey.toCoseKey()
            } else null


        @Deprecated("Use above instead")
        fun fromCoordinates(
            type: CoseKeyType,
            curve: CoseEllipticCurve,
            x: ByteArray,
            y: ByteArray
        ): CoseKey? = CryptoPublicKey.Ec.fromCoordinates(curve.toJwkCurve(), x, y).toCoseKey()

    }
}

/**
 * Converts [CryptoPublicKey] into a [CoseKey]
 * If [algorithm] is not set then key can be used for any algorithm with same kty (RFC 8152), throws [IllegalArgumentException] for invalid kty/algorithm pairs
 */
@Throws(Throwable::class)
fun CryptoPublicKey.toCoseKey(algorithm: CoseAlgorithm? = null): CoseKey =
    when (this) {
        is CryptoPublicKey.Ec ->
            if ((algorithm != null) && (algorithm != when (curve) {
                    EcCurve.SECP_256_R_1 -> CoseAlgorithm.ES256
                    EcCurve.SECP_384_R_1 -> CoseAlgorithm.ES384
                    EcCurve.SECP_521_R_1 -> CoseAlgorithm.ES512
                })
            ) throw IllegalArgumentException("Algorithm and Key Type mismatch")
            else CoseKey(
                keyParams = CoseKeyParams.EcYByteArrayParams(
                    curve = curve.toCoseCurve(),
                    x = x,
                    y = y
                ),
                type = CoseKeyType.EC2,
                keyId = keyId.encodeToByteArray(),
                algorithm = algorithm
            )

        is CryptoPublicKey.Rsa ->
            if ((algorithm != null) && (algorithm !in listOf(
                    CoseAlgorithm.PS256, CoseAlgorithm.PS384, CoseAlgorithm.PS512,
                    CoseAlgorithm.RS256, CoseAlgorithm.RS384, CoseAlgorithm.RS512
                ))
            ) throw IllegalArgumentException("Algorithm and Key Type mismatch")
            else CoseKey(
                keyParams = CoseKeyParams.RsaParams(
                    n = n,
                    e = e.encodeToByteArray()
                ),
                type = CoseKeyType.RSA,
                keyId = keyId.encodeToByteArray(),
                algorithm = algorithm
            )
    }

private const val COSE_KID = "coseKid"
var CryptoPublicKey.coseKid: String
    get() = additionalProperties[COSE_KID] ?: keyId
    set(value) {
        additionalProperties[COSE_KID] = value
    }


@OptIn(ExperimentalSerializationApi::class)
object CoseKeySerializer : KSerializer<CoseKey> {

    @Serializable
    private class CoseKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @SerialLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null
    ) {
        constructor(src: CoseKey) : this(
            src.type,
            src.keyId,
            src.algorithm,
            src.operations,
            src.baseIv,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.curve else null,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.x else null,
            if (src.keyParams is CoseKeyParams.EcYByteArrayParams) src.keyParams.y else null,
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.n
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.e
                else -> null
            },
            when (val params = src.keyParams) {
                is CoseKeyParams.RsaParams -> params.d
                is CoseKeyParams.EcYByteArrayParams -> params.d
                else -> null
            },

            )
    }

    private interface SerialContainer {
        fun toCoseKey(): CoseKey
    }


    @Serializable
    private class CoseEcKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("crv")
        val curve: CoseEllipticCurve? = null,
        @SerialLabel(-2)
        @SerialName("x")
        @ByteString
        val x: ByteArray? = null,
        @SerialLabel(-3)
        @SerialName("y")
        @ByteString
        val y: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.EC2) throw IllegalArgumentException("Not an EC key!")
        }

        override fun toCoseKey() =
            CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.EcYByteArrayParams(curve, x, y, d))

    }


    @Serializable
    private class CoseRsaKeySerialContainer(
        @SerialLabel(1)
        @SerialName("kty")
        val type: CoseKeyType,
        @SerialLabel(2)
        @SerialName("kid")
        @ByteString
        val keyId: ByteArray? = null,
        @SerialLabel(3)
        @SerialName("alg")
        val algorithm: CoseAlgorithm? = null,
        @SerialLabel(4)
        @SerialName("key_ops")
        val operations: Array<CoseKeyOperation>? = null,
        @SerialLabel(5)
        @SerialName("Base IV")
        @ByteString
        val baseIv: ByteArray? = null,
        @SerialLabel(-1)
        @SerialName("n")
        val n: ByteArray? = null,
        @SerialLabel(-2)
        @SerialName("e")
        @ByteString
        val e: ByteArray? = null,
        @SerialLabel(-4)
        @SerialName("d")
        @ByteString
        val d: ByteArray? = null
    ) : SerialContainer {
        init {
            if (type != CoseKeyType.RSA) throw IllegalArgumentException("Not an RSA key!")
        }

        override fun toCoseKey() = CoseKey(type, keyId, algorithm, operations, baseIv, CoseKeyParams.RsaParams(n, e, d))
    }

    override val descriptor: SerialDescriptor
        get() = CoseKeySerialContainer.serializer().descriptor

    override fun deserialize(decoder: Decoder): CoseKey {
        val labels = mapOf<String, Long>(
            "kty" to 1,
            "kid" to 2,
            "alg" to 3,
            "key_ops" to 4,
            "Base IV" to 5,
            "n/crv" to -1,
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

        decoder.decodeStructure(descriptor) {
            while (true) {
                val index = decodeElementIndex(descriptor)
                if (index == -1) break
                val label = descriptor.getElementAnnotations(index).filterIsInstance<SerialLabel>().first().label
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

                    labels["n/crv"] -> {
                        when (type) {
                            CoseKeyType.EC2 -> {
                                val deser = CoseEllipticCurveSerializer
                                crv = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.RSA -> {
                                val deser = ByteArraySerializer()
                                n = decodeNullableSerializableElement(deser.descriptor, index, deser)
                            }

                            CoseKeyType.SYMMETRIC -> {}
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
                            ByteArraySerializer().descriptor,
                            index,
                            ByteArraySerializer()
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
                CoseEcKeySerialContainer(type, keyId, alg, keyOps, baseIv, crv, xOrE, y, d).toCoseKey()
            }

            CoseKeyType.RSA -> {
                CoseRsaKeySerialContainer(type, keyId, alg, keyOps, baseIv, n, xOrE, d).toCoseKey()
            }

            CoseKeyType.SYMMETRIC -> CoseKey(type, keyId, alg, keyOps, keyParams = null)
        }
    }

    override fun serialize(encoder: Encoder, value: CoseKey) {
        encoder.encodeSerializableValue(CoseKeySerialContainer.serializer(), CoseKeySerialContainer(value))
    }

}