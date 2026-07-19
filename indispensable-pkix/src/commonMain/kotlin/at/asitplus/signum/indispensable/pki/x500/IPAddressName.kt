package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.encoding.encodeToAsn1OctetStringPrimitive
import at.asitplus.cidre.*
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.x500.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.x500.GeneralName.X509Representable.Descriptor
import at.asitplus.signum.indispensable.pki.x500.GeneralName.NameType

/** RFC 5280 `iPAddress` GeneralName CHOICE `[7]`. */
class IPAddressName internal constructor(
    val address: IpAddress<*, *>?,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    val rawBytes: ByteArray,
    performValidation: Boolean,
) : AbstractX509GeneralName(NameType.IP, rawBytes.encodeToAsn1OctetStringPrimitive() withImplicitTag contextTag(7u)) {

    override val isValid: Boolean by lazy { address != null }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid IpAddressName.")
    }

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(address: IpAddress<*, *>, addressAndPrefix: IpAddressAndPrefix<*, *>? = null)
            : this(address, addressAndPrefix, addressAndPrefix?.toX509Octets() ?: address.octets, true)

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(addressAndPrefix: IpAddressAndPrefix<*, *>)
            : this(addressAndPrefix.address, addressAndPrefix, addressAndPrefix.toX509Octets(), true)

    val network: IpNetwork<*, *>? by lazy {
        when (addressAndPrefix) {
            is IpInterface<*, *> -> addressAndPrefix.network
            is IpNetwork<*, *> -> addressAndPrefix
            else -> null
        }
    }

    override fun toString(): String = addressAndPrefix?.toString() ?: address.toString()

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {

            val other = input as? IPAddressName ?: return ConstraintResult.DIFF_TYPE

            if (this == other) return ConstraintResult.MATCH

            val thisNetwork = network
            val otherNetwork = other.network
            val thisAddress = address
            val otherAddress = other.address

            when {
                thisNetwork == null && otherNetwork == null -> {
                    thisAddress!!.withSameFamily(otherAddress!!) {
                        ConstraintResult.SAME_TYPE
                    } ?: ConstraintResult.DIFF_TYPE
                }

                thisNetwork != null && otherNetwork != null -> {
                    thisNetwork.withSameFamily(otherNetwork) {
                        when {
                            left == right -> ConstraintResult.MATCH
                            left.contains(right) -> ConstraintResult.WIDENS
                            right.contains(left) -> ConstraintResult.NARROWS
                            else -> ConstraintResult.SAME_TYPE
                        }
                    } ?: ConstraintResult.DIFF_TYPE
                }

                thisNetwork != null && otherAddress != null -> {
                    thisNetwork.withSameFamily(otherAddress) {
                        if (network.contains(address)) {
                            ConstraintResult.WIDENS
                        } else {
                            ConstraintResult.SAME_TYPE
                        }
                    } ?: ConstraintResult.DIFF_TYPE
                }

                thisAddress != null && otherNetwork != null -> {
                    thisAddress.withSameFamily(otherNetwork) {
                        if (network.contains(address)) {
                            ConstraintResult.NARROWS
                        } else {
                            ConstraintResult.SAME_TYPE
                        }
                    } ?: ConstraintResult.DIFF_TYPE
                }

                else -> ConstraintResult.SAME_TYPE
            }
        }
    }

    companion object : Descriptor {
        override val type = NameType.IP

        override fun fromAsn1Representation(src: Asn1Element): IPAddressName {
            val content = src.asPrimitive().content
            return when (content.size) {
                IpFamily.V4.numberOfOctets -> IPAddressName(
                    IpAddress.V4(content), rawBytes = IpAddress.V4(content).octets, performValidation = false
                )

                IpFamily.V6.numberOfOctets -> IPAddressName(
                    IpAddress.V6(content), rawBytes = IpAddress.V6(content).octets, performValidation = false
                )

                else -> IPAddressName(IpInterface.fromX509Octets(content))
            }
        }

        /**
         * @throws IllegalArgumentException if an invalid string is provided
         * @throws Asn1Exception if an invalid address is provided
         */
        @Throws(Asn1Exception::class, IllegalArgumentException::class)
        fun fromString(stringRepresentation: String): IPAddressName = runCatching {
            IPAddressName(IpInterface(stringRepresentation))
        }.getOrElse {
            IPAddressName(IpAddress(stringRepresentation))
        }
    }
}
