package at.asitplus.signum.indispensable.digest

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.X509AlgorithmIdentifier
import at.asitplus.signum.Enumerable
import at.asitplus.signum.Enumeration
import at.asitplus.signum.indispensable.SourceRepresentationStorage
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import at.asitplus.signum.indispensable.mac.Asn1MACAlgorithmProvider
import at.asitplus.signum.indispensable.mac.HMAC
import at.asitplus.signum.indispensable.mac.MessageAuthenticationCode
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import kotlinx.serialization.builtins.serializer

/** Digest values compare by algorithm name; retained source representations belong to each instance. */
sealed class WellKnownDigest(
    override val name: String,
    override val inputBlockSize: BitLength, override val outputLength: BitLength,
    val oid: ObjectIdentifier
) : Digest, Enumerable {

    override val sourceRepresentation = SourceRepresentationStorage()

    class SHA1 : WellKnownDigest("SHA1", 512.bit, 160.bit, KnownOIDs.sha1)
    class SHA256 : WellKnownDigest("SHA256", 512.bit, 256.bit, KnownOIDs.sha_256)
    class SHA384 : WellKnownDigest("SHA384", 1024.bit, 384.bit, KnownOIDs.sha_384)
    class SHA512 : WellKnownDigest("SHA512", 1024.bit, 512.bit, KnownOIDs.sha_512)

    final override fun equals(other: Any?) = other is WellKnownDigest && name == other.name
    final override fun hashCode() = name.hashCode()
    final override fun toString() = name

    /** A value-equal digest with independent, initially empty source storage. */
    internal fun freshInstance(): WellKnownDigest = when (this) {
        is SHA1 -> SHA1()
        is SHA256 -> SHA256()
        is SHA384 -> SHA384()
        is SHA512 -> SHA512()
    }

    companion object : Enumeration<WellKnownDigest> {
        val SHA1 = SHA1()
        val SHA256 = SHA256()
        val SHA384 = SHA384()
        val SHA512 = SHA512()
        override val entries: Iterable<WellKnownDigest> by lazy { setOf(SHA1, SHA256, SHA384, SHA512) }
    }

    object Serializer : TransformingSerializerTemplate<WellKnownDigest, String>(
        parent = String.serializer(),
        encodeAs = WellKnownDigest::toString,
        decodeAs = { s -> entries.first { it.name == s }.freshInstance() }
    )
}

object IndispensableDigestsAlgorithmProviderAsn1: Asn1DigestAlgorithmProvider {
    override fun encodeToAsn1(value: Digest): X509AlgorithmIdentifier? =
        (value as? WellKnownDigest)?.let { X509AlgorithmIdentifier(it.oid, null) }

    override fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier): Digest? {
        return WellKnownDigest.entries.firstOrNull { it.oid == algorithmIdentifier.oid }?.let {
            val params = algorithmIdentifier.parameters
            // parameters must be either absent (kotlin null) or NULL (ASN.1 null)
            if (params != null) require(params == Asn1Null)
            it.freshInstance()
        }
    }
}

object IndispensableHMACProvider: Asn1MACAlgorithmProvider {
    override fun encodeToAsn1(value: MessageAuthenticationCode): X509AlgorithmIdentifier? =
        (value as? HMAC)?.let { X509AlgorithmIdentifier(it.oid, Asn1Null) }

    override fun decodeFromAsn1(algorithmIdentifier: X509AlgorithmIdentifier): MessageAuthenticationCode? {
        if (algorithmIdentifier.parameters != Asn1Null) return null
        return WellKnownDigest.entries.asSequence().map(HMAC::byDigest)
            .first { it.oid == algorithmIdentifier.oid }
    }
}
