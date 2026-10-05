package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.Decodable
import at.asitplus.signum.indispensable.Encodable
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * Certificate extension independent of its encoding format
 */
interface CertificateExtension : Identifiable, Encodable {

    val critical: Boolean

    /**
     * Describes a typed [CertificateExtension] extension and knows how to construct it from its
     * generic awesn1 representation. Mirrors [AttributeTypeAndValue.Descriptor]; register custom
     * extension types via [register].
     */
    interface Descriptor : Identifiable {
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): CertificateExtension
        fun register(): Descriptor = Registry.register(this)
    }

    /**
     * Maps extension OIDs to their typed [Descriptor]s for the certificate-decode upgrade path.
     *
     * Registration is **startup-only**: descriptors must be registered (via [register], e.g. from
     * `SignumPkix.install()`) **before the first (de)serialization**. The registry seals on its first
     * lookup — after that it is immutable and reads are lock-free; later [register] calls throw. This
     * mirrors the `DefaultDer.register` contract.
     */
    @OptIn(ExperimentalAtomicApi::class)
    object Registry {
        private val descriptors = mutableMapOf<ObjectIdentifier, Descriptor>()
        private val sealed = AtomicReference<Map<ObjectIdentifier, Descriptor>?>(null)

        fun register(descriptor: Descriptor): Descriptor {
            check(sealed.load() == null) {
                "CertificateExtension registry is sealed; register before the first (de)serialization."
            }
            descriptors[descriptor.oid] = descriptor
            return descriptor
        }

        fun descriptorFor(oid: ObjectIdentifier): Descriptor? = view()[oid]

        private fun view(): Map<ObjectIdentifier, Descriptor> =
            sealed.load() ?: descriptors.toMap().also { sealed.store(it) }
    }

    companion object : Decodable<CertificateExtension> {
        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: ByteArray,
        ): CertificateExtension = X509CertificateExtension(oid, critical, value)

        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: Asn1OctetString,
        ): CertificateExtension = X509CertificateExtension(oid, critical, value)

        operator fun invoke(asn1Representation: Awesn1X509CertificateExtension): CertificateExtension =
            fromAsn1Representation(asn1Representation)

        /**
         * Upgrades the generic awesn1 [src] extension to a registered typed extension (e.g. a
         * `KeyUsageExtension` from `indispensable-pkix`) when a [Descriptor] is registered for its
         * OID, falling back to a generic [X509CertificateExtension] otherwise. Decoding failures of
         * a typed extension also fall back to the generic representation rather than throwing.
         */
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): CertificateExtension =
            Registry.descriptorFor(src.oid)?.let { descriptor ->
                catchingUnwrapped { descriptor.fromAsn1Representation(src) }.getOrNull()
            } ?: X509CertificateExtension(src)

    }
}
