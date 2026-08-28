package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.indispensable.integrity.HMAC
import at.asitplus.signum.indispensable.integrity.MessageAuthenticationCode
import at.asitplus.signum.indispensable.integrity.MessageAuthenticationCodeProvider
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer

@Serializable(with = WellKnownDigest.Serializer::class)
sealed class WellKnownDigest(
    override val name: String,
    override val inputBlockSize: BitLength, override val outputLength: BitLength,
    val oid: ObjectIdentifier
) : Digest, Enumerable {

    data object SHA1 : WellKnownDigest("SHA1", 512.bit, 160.bit, KnownOIDs.sha1)
    data object SHA256 : WellKnownDigest("SHA256", 512.bit, 256.bit, KnownOIDs.sha_256)
    data object SHA384 : WellKnownDigest("SHA384", 1024.bit, 384.bit, KnownOIDs.sha_384)
    data object SHA512 : WellKnownDigest("SHA512", 1024.bit, 512.bit, KnownOIDs.sha_512)

    override val asn1Representation: X509AlgorithmIdentifier
        get() = X509AlgorithmIdentifier(oid, null)

    companion object : Enumeration<WellKnownDigest> {
        override val entries: Iterable<WellKnownDigest> by lazy { setOf(SHA1, SHA256, SHA384, SHA512) }
    }

    object Serializer : TransformingSerializerTemplate<WellKnownDigest, String>(
        parent = String.serializer(),
        encodeAs = WellKnownDigest::toString,
        decodeAs = { s -> entries.first { it.name == s } }
    )
}

object IndispensableDigestsProvider: DigestProvider {
    override fun getDigest(algorithmIdentifier: X509AlgorithmIdentifier): Digest? {
        return WellKnownDigest.entries.firstOrNull { it.oid == algorithmIdentifier.oid }?.also {
            val params = algorithmIdentifier.parameters
            // parameters must be either absent (kotlin null) or NULL (ASN.1 null)
            if (params != null) require(params == Asn1Null)
        }
    }
}

object IndispensableHMACProvider: MessageAuthenticationCodeProvider {
    override fun getMAC(algorithmIdentifier: X509AlgorithmIdentifier): MessageAuthenticationCode? {
        if (algorithmIdentifier.parameters != Asn1Null) return null
        return WellKnownDigest.entries.asSequence().map(HMAC::byDigest)
            .first { it.oid == algorithmIdentifier.oid }
    }
}
