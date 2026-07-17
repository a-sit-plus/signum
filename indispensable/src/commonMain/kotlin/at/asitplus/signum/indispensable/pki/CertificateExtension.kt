package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.encoding.parse
import at.asitplus.awesn1.serialization.Der
import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.DerDecodable
import at.asitplus.signum.indispensable.DerEncodable
import at.asitplus.signum.internals.orLazy
import kotlin.concurrent.atomics.AtomicReference
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.serialization.KSerializer
import at.asitplus.awesn1.crypto.pki.X509CertificateExtension as Awesn1X509CertificateExtension

/**
 * X.509 Certificate Extension
 */
sealed interface CertificateExtension : Identifiable {

    val critical: Boolean
    sealed interface X509Representable : CertificateExtension, DerEncodable<Awesn1X509CertificateExtension> {
        val derEncodedValue: ByteArray
    }

    /**
     * Describes a typed [X509Representable] extension and knows how to construct it from its
     * generic awesn1 representation. Mirrors [AttributeTypeAndValue.Descriptor]; register custom
     * extension types via [register].
     */
    interface Descriptor : Identifiable {
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): X509Representable
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

    companion object : DerDecodable<Awesn1X509CertificateExtension, X509Representable> {
        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: ByteArray,
        ): X509Representable = X509CertificateExtension(oid, critical, value)

        operator fun invoke(
            oid: ObjectIdentifier,
            critical: Boolean = false,
            value: Asn1OctetString,
        ): X509Representable = X509CertificateExtension(oid, critical, value)

        operator fun invoke(asn1Representation: Awesn1X509CertificateExtension): X509Representable =
            fromAsn1Representation(asn1Representation)

        /**
         * Upgrades the generic awesn1 [src] extension to a registered typed extension (e.g. a
         * `KeyUsageExtension` from `indispensable-pkix`) when a [Descriptor] is registered for its
         * OID, falling back to a generic [X509CertificateExtension] otherwise. Decoding failures of
         * a typed extension also fall back to the generic representation rather than throwing.
         */
        fun fromAsn1Representation(src: Awesn1X509CertificateExtension): X509Representable =
            Registry.descriptorFor(src.oid)?.let { descriptor ->
                catchingUnwrapped { descriptor.fromAsn1Representation(src) }.getOrNull()
            } ?: X509CertificateExtension(src)

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(
            serializer: KSerializer<Awesn1X509CertificateExtension>,
            src: Asn1Element,
            der: Der,
        ): X509Representable =
            fromAsn1Representation(der.decodeFromTlv(serializer, src))
    }
}

open class X509CertificateExtension private constructor(
    providedAsn1Representation: Awesn1X509CertificateExtension?,
    override val oid: ObjectIdentifier,
    override val critical: Boolean,
    override val derEncodedValue: ByteArray,
) : CertificateExtension.X509Representable {


    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: ByteArray,
    ) : this(null, oid, critical, value)

    constructor(
        oid: ObjectIdentifier,
        critical: Boolean = false,
        value: Asn1OctetString,
    ) : this(oid, critical, value.content)

    constructor(asn1Representation: Awesn1X509CertificateExtension) : this(
        asn1Representation,
        asn1Representation.oid,
        asn1Representation.critical,
        asn1Representation.value,
    )

    override val asn1Representation: Awesn1X509CertificateExtension by providedAsn1Representation orLazy {
        Awesn1X509CertificateExtension(oid, critical, derEncodedValue)
    }

    /**
     * The (parsed) ASN.1 structure carried inside this extension's `extnValue` OCTET STRING,
     * i.e. the typed inner value typed extensions decode from.
     */
    val decodedValue: Asn1Element by lazy { Asn1Element.parse(derEncodedValue) }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is X509CertificateExtension) return false
        return oid == other.oid && critical == other.critical && derEncodedValue.contentEquals(other.derEncodedValue)
    }

    override fun hashCode(): Int {
        var result = oid.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + derEncodedValue.contentHashCode()
        return result
    }

    override fun toString(): String =
        "CertificateExtension(oid=$oid, critical=$critical, value=${derEncodedValue.contentToString()})"
}

internal fun CertificateExtension.requireX509(): CertificateExtension.X509Representable =
    this as? CertificateExtension.X509Representable
        ?: throw Asn1Exception("Certificate extension $oid has no X.509/DER representation")
