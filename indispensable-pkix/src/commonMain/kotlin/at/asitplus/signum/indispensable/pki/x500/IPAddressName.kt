package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.cidre.*

/** RFC 5280 `iPAddress` GeneralName CHOICE `[7]`. */
class IPAddressName internal constructor(
    val address: IpAddress<*, *>?,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    private val unparsedBytes: ByteArray?,
) : AbstractGeneralName() {
    val rawBytes: ByteArray get() = unparsedBytes ?: addressAndPrefix?.toX509Octets() ?: requireNotNull(address).octets
    override val equalityValue get() = rawBytes

    init {
        if (address == null) throw Asn1Exception("Invalid IpAddressName.")
    }

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(address: IpAddress<*, *>, addressAndPrefix: IpAddressAndPrefix<*, *>? = null)
            : this(address, addressAndPrefix, null)

    /**
     * @throws Asn1Exception if illegal IpAddress is provided
     */
    @Throws(Asn1Exception::class)
    constructor(addressAndPrefix: IpAddressAndPrefix<*, *>)
            : this(addressAndPrefix.address, addressAndPrefix, null)

    val network: IpNetwork<*, *>? by lazy {
        when (addressAndPrefix) {
            is IpInterface<*, *> -> addressAndPrefix.network
            is IpNetwork<*, *> -> addressAndPrefix
            else -> null
        }
    }

    override fun toString(): String = addressAndPrefix?.toString() ?: address.toString()

    companion object {
        val tag = X509GeneralName.Tags.ipAddress

        internal fun fromAsn1Model(src: X509GeneralName): IPAddressName {
            val content = (src as X509GeneralName.IpAddress).rawValue.content
            return when (content.size) {
                IpFamily.V4.numberOfOctets -> IPAddressName(
                    IpAddress.V4(content), unparsedBytes = content,

                )

                IpFamily.V6.numberOfOctets -> IPAddressName(
                    IpAddress.V6(content), unparsedBytes = content,

                )

                else -> IpInterface.fromX509Octets(content).let {
                    IPAddressName(it.address, it, content)
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
