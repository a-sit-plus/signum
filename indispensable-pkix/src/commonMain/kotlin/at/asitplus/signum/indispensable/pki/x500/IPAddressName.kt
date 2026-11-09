package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.cidre.*
import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.x500.ConstraintResult

/** RFC 5280 `iPAddress` GeneralName CHOICE `[7]`. */
class IPAddressName internal constructor(
    val address: IpAddress<*, *>?,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    private val unparsedBytes: ByteArray?,
    performValidation: Boolean,
) : AbstractGeneralName() {
    val rawBytes: ByteArray get() = unparsedBytes ?: addressAndPrefix?.toX509Octets() ?: requireNotNull(address).octets
    override val equalityValue get() = rawBytes

    override val isValid: Boolean by lazy { address != null }

    init {
        if (performValidation && !isValid) throw Asn1Exception("Invalid IpAddressName.")
    }

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(address: IpAddress<*, *>, addressAndPrefix: IpAddressAndPrefix<*, *>? = null)
            : this(address, addressAndPrefix, null, true)

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(addressAndPrefix: IpAddressAndPrefix<*, *>)
            : this(addressAndPrefix.address, addressAndPrefix, null, true)

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

    companion object {
        val tag = X509GeneralName.Tags.ipAddress

        internal fun fromAsn1Model(src: X509GeneralName): IPAddressName {
            val content = (src as X509GeneralName.IpAddress).rawValue.content
            return when (content.size) {
                IpFamily.V4.numberOfOctets -> IPAddressName(
                    IpAddress.V4(content), unparsedBytes = content, performValidation = false,

                )

                IpFamily.V6.numberOfOctets -> IPAddressName(
                    IpAddress.V6(content), unparsedBytes = content, performValidation = false,

                )

                else -> IpInterface.fromX509Octets(content).let {
                    IPAddressName(it.address, it, content, false)
                }
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
