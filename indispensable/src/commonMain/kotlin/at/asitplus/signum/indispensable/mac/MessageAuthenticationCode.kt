package at.asitplus.signum.indispensable.mac

import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.awesn1.runRethrowing
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import at.asitplus.signum.indispensable.Indispensable

interface MessageAuthenticationCode : Encodable {
    /** output size of MAC */
    val outputLength: BitLength

    @ConsistentCopyVisibility
    data class Truncated
    internal constructor(val inner: MessageAuthenticationCode, override val outputLength: BitLength)
        : MessageAuthenticationCode
    {
        override fun toString() = "$inner (truncated to $outputLength)"
        override val representations: Map<Encodable.Representation, Any> = emptyMap()

    }

    fun truncatedTo(length: BitLength): MessageAuthenticationCode = when {
        this is Truncated -> this.inner.truncatedTo(length)
        else -> when {
            length <= 0.bit -> throw IllegalArgumentException("Cannot truncate to $outputLength <= 0")
            length < this.outputLength -> Truncated(this, length)
            length == this.outputLength -> this
            else -> throw IllegalArgumentException("Cannot truncate $this to $outputLength bits (its own output length is only ${this.outputLength} bits")
        }
    }

    companion object : Decodable<MessageAuthenticationCode> {
        init { Indispensable.init() }

        fun fromAsn1Representation(element: X509AlgorithmIdentifier): MessageAuthenticationCode = runRethrowing {
            ServiceLoader.load<MessageAuthenticationCodeProvider>()
                .get(element, MessageAuthenticationCodeProvider::getMAC)
        }
    }
}

suspend fun MessageAuthenticationCode.mac(key: ByteArray, msg: Sequence<ByteArray>): ByteArray =
    ServiceLoader.load<MessageAuthenticationCodeOperationProvider>()
        .get(this@mac) { doMAC(it, key, msg) }
suspend fun MessageAuthenticationCode.mac(key: ByteArray, msg: ByteArray) = mac(key, sequenceOf(msg))
suspend fun MessageAuthenticationCode.mac(key: ByteArray, msg: Iterable<ByteArray>) = mac(key, msg.asSequence())
suspend fun SpecializedMessageAuthenticationCode.mac(key: ByteArray, msg: Sequence<ByteArray>) = algorithm.mac(key, msg)
suspend fun SpecializedMessageAuthenticationCode.mac(key: ByteArray, msg: ByteArray) = algorithm.mac(key, sequenceOf(msg))
suspend fun SpecializedMessageAuthenticationCode.mac(key: ByteArray, msg: Iterable<ByteArray>) = algorithm.mac(key, msg.asSequence())

interface SpecializedMessageAuthenticationCode {
    val algorithm: MessageAuthenticationCode
}

// @Service
interface MessageAuthenticationCodeProvider {
    /** Parse a [MessageAuthenticationCode] from its [X509AlgorithmIdentifier] form */
    fun getMAC(algorithmIdentifier: X509AlgorithmIdentifier): MessageAuthenticationCode?
}

// @Service
interface MessageAuthenticationCodeOperationProvider {
    /** If the [mac] is recognized, perform the MAC operation with the given [key] and [message] */
    suspend fun doMAC(mac: MessageAuthenticationCode, key: ByteArray, message: Sequence<ByteArray>): ByteArray?
}
