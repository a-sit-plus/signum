package at.asitplus.signum.indispensable

import at.asitplus.awesn1.serialization.DER
import at.asitplus.awesn1.serialization.Der
import at.asitplus.signum.indispensable.pki.Certificate
import at.asitplus.signum.indispensable.pki.CertificateDerCodec
import at.asitplus.signum.indispensable.pki.TbsCertificate
import at.asitplus.signum.indispensable.pki.TbsCertificateDerCodec
import kotlin.reflect.KClass

/** Converts a Signum value to/from DER; implementations own structural conversion. */
interface DerCodec<T : Encodable> {
    val type: KClass<T>
    fun encode(value: T, der: Der): ByteArray
    fun decode(bytes: ByteArray, der: Der): T
}

/** Default codecs are available automatically. Register additional codecs at startup. */
object DerCodecs {
    private val codecs = mutableMapOf<Decodable<*>, DerCodec<*>>(
        TbsCertificate to TbsCertificateDerCodec,
        Certificate to CertificateDerCodec,
    )

    fun <T : Encodable> register(target: Decodable<T>, codec: DerCodec<T>) {
        codecs[target] = codec
    }

    @Suppress("UNCHECKED_CAST")
    internal fun encode(value: Encodable, der: Der): ByteArray {
        val codec = codecs.values.firstOrNull { it.type == value::class }
            ?: throw IllegalArgumentException("No DER codec for ${value::class.simpleName}")
        return (codec as DerCodec<Encodable>).encode(value, der)
    }

    @Suppress("UNCHECKED_CAST")
    internal fun <T : Encodable> decode(target: Decodable<T>, bytes: ByteArray, der: Der): T {
        val codec = codecs[target] ?: throw IllegalArgumentException("No DER codec for decoding target")
        return (codec as DerCodec<T>).decode(bytes, der)
    }
}

fun Encodable.encode(format: Der): ByteArray = DerCodecs.encode(this, format)
fun <T : Encodable> Decodable<T>.decode(bytes: ByteArray, format: Der): T = DerCodecs.decode(this, bytes, format)

/** Compatibility for existing TbsCertificate signing consumers during this prototype. */
fun TbsCertificate.encodeToDer(der: Der = DER): ByteArray = encode(der)
