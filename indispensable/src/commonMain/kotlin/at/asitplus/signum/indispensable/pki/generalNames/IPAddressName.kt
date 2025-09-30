package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpAddressAndPrefix
import at.asitplus.cidre.IpFamily
import at.asitplus.cidre.IpInterface
import at.asitplus.cidre.IpNetwork
import at.asitplus.cidre.byteops.toNetmask
import at.asitplus.cidre.byteops.toPrefix
import at.asitplus.cidre.isV4
import at.asitplus.cidre.isV6
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive
import kotlinx.io.IOException

data class IPAddressName internal constructor(
    val address: IpAddress<*, *>?,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    val rawBytes: ByteArray,
    override val performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.IP
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    /**
     * Always `true`, since creation of [IPAddressName] is only possible if the
     * underlying [IpAddress] or [IpAddressAndPrefix] are valid
     */
    override val isValid: Boolean = address != null

    /**
     * @throws Asn1Exception if illegal IpAddressName is provided
     */
    @Throws(Asn1Exception::class)
    constructor(
        address: IpAddress<*, *>? = null,
        addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    // TODO remove rawBytes param, use CIDRE method for calculating rawBytes
        rawBytes: ByteArray
    ) : this (address, addressAndPrefix, rawBytes, true) {
        if (!isValid) throw Asn1Exception("Invalid IpAddressName.")
    }

    val network: IpNetwork<*, *>? by lazy {
        when (addressAndPrefix) {
            is IpInterface<*, *> -> addressAndPrefix.network
            is IpNetwork<*, *> -> addressAndPrefix
            else -> null
        }
    }

    override fun encodeToTlv(): Asn1Primitive {
        return rawBytes.encodeToAsn1OctetStringPrimitive()
    }

    companion object : Asn1Decodable<Asn1Primitive, IPAddressName> {

        override fun doDecode(src: Asn1Primitive): IPAddressName {
            val content = src.content
            return when (content.size) {
                IpFamily.V4.numberOfOctets -> IPAddressName(IpAddress.V4(content), rawBytes = IpAddress.V4(content).octets)
                IpFamily.V6.numberOfOctets -> IPAddressName(IpAddress.V6(content), rawBytes = IpAddress.V6(content).octets)
                2 * IpFamily.V4.numberOfOctets -> createNetworkV4(content)
                2 * IpFamily.V6.numberOfOctets -> createNetworkV6(content)
                else -> throw IOException("Invalid IP/Network length: ${content.size}")
            }
        }
        //TODO change after CIDRE update
        private fun createNetworkV4(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V4(bytes.copyOfRange(0, 4))
            val prefix = bytes.copyOfRange(4, 8).toPrefix()
            return IPAddressName(address, addressAndPrefix = IpInterface.V4(address, prefix), address.octets + prefix.toNetmask(4))
        }
        //TODO change after CIDRE update
        private fun createNetworkV6(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V6(bytes.copyOfRange(0, 16))
            val prefix = bytes.copyOfRange(16, 32).toPrefix()
            return IPAddressName(address, addressAndPrefix = IpInterface.V6(address, prefix), address.octets + prefix.toNetmask(16))
        }

        @Throws(Asn1Exception::class)
        fun fromString(name: String): IPAddressName =
            runCatching {
                IpInterface(name).let { iface ->
                    IPAddressName(iface.address, iface, iface.address.octets + iface.netmask)
                }
            }.getOrElse {
                val addr = IpAddress(name)
                IPAddressName(addr, null, addr.octets)
            }
    }

    override fun toString(): String = addressAndPrefix?.toString() ?: address.toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IPAddressName

        if (performValidation != other.performValidation) return false
        if (isValid != other.isValid) return false
        if (address != other.address) return false
        if (addressAndPrefix != other.addressAndPrefix) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = performValidation.hashCode()
        result = 31 * result + isValid.hashCode()
        result = 31 * result + address.hashCode()
        result = 31 * result + (addressAndPrefix?.hashCode() ?: 0)
        result = 31 * result + type.hashCode()
        return result
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (!isValid || input?.isValid == false) throw Asn1Exception("Invalid IpAddressName")
        if (input !is IPAddressName) return GeneralNameOption.ConstraintResult.DIFF_TYPE
        if (this == input) return GeneralNameOption.ConstraintResult.MATCH

        if (network == null && input.network == null &&
            ((address!!.isV4() && input.address!!.isV4()) || (address.isV6() && input.address!!.isV6()))) {
            return GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        // Subnet vs Subnet
        if (network != null && input.network != null) {
            val thisNet = network as IpNetwork<Number, Any>
            val otherNet = input.network as IpNetwork<Number, Any>
            when {
                thisNet == otherNet -> GeneralNameOption.ConstraintResult.MATCH
                thisNet.contains(otherNet) -> GeneralNameOption.ConstraintResult.WIDENS
                otherNet.contains(thisNet) -> GeneralNameOption.ConstraintResult.NARROWS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }

        // Other is subnet, this is host
        if (network != null) {
            val thisNet = network as IpNetwork<Number, Any>
            val otherAddress = input.address as IpAddress<Number, Any>
            return if (thisNet.contains(otherAddress))
                GeneralNameOption.ConstraintResult.WIDENS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        // Other is subnet, this is host
        if (input.network != null) {
            val thisAddress = address as IpAddress<Number, Any>
            val otherNet = input.network as IpNetwork<Number, Any>
            return if (otherNet.contains(thisAddress))
                GeneralNameOption.ConstraintResult.NARROWS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        return GeneralNameOption.ConstraintResult.SAME_TYPE
    }
}
