package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpNetwork
import at.asitplus.cidre.byteops.toPrefix
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive
import kotlinx.io.IOException

class IPAddressName(
    val address: IpAddress<*>,
    val networkV4: IpNetwork.V4? = null,
    val networkV6: IpNetwork.V6? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.IP
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    override fun encodeToTlv(): Asn1Primitive {
        val bytes = when {
            networkV4 != null -> networkV4.address.octets + networkV4.netmask
            networkV6 != null -> networkV6.address.octets + networkV6.netmask
            else -> address.octets
        }
        return bytes.encodeToAsn1OctetStringPrimitive()
    }

    companion object : Asn1Decodable<Asn1Primitive, IPAddressName> {

        override fun doDecode(src: Asn1Primitive): IPAddressName {
            val content = src.content
            return when (content.size) {
                4 -> IPAddressName(IpAddress.V4(content))
                16 -> IPAddressName(IpAddress.V6(content))
                8 -> createNetworkV4(content)
                32 -> createNetworkV6(content)
                else -> throw IOException("Invalid IP/Network length: ${content.size}")
            }
        }

        private fun createNetworkV4(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V4(bytes.copyOfRange(0, 4))
            val prefix = bytes.copyOfRange(4, 8).toPrefix()
            return IPAddressName(address, networkV4 = IpNetwork.V4(address, prefix))
        }

        private fun createNetworkV6(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V6(bytes.copyOfRange(0, 16))
            val prefix = bytes.copyOfRange(16, 32).toPrefix()
            return IPAddressName(address, networkV6 = IpNetwork.V6(address, prefix))
        }

        @Throws(IOException::class)
        fun fromString(name: String): IPAddressName {
            return when (val network = IpNetwork(name)) {
                is IpNetwork.V4 -> IPAddressName(network.address, networkV4 = network)
                is IpNetwork.V6 -> IPAddressName(network.address, networkV6 = network)
                else -> throw IllegalArgumentException("Unknown network type")
            }
        }
    }

    override fun toString(): String = networkV4?.toString() ?: networkV6?.toString() ?: address.toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IPAddressName

        if (address != other.address) return false
        if (networkV4 != other.networkV4) return false
        if (networkV6 != other.networkV6) return false
        if (type != other.type) return false

        return true
    }

    override fun hashCode(): Int {
        var result = address.hashCode()
        result = 31 * result + (networkV4?.hashCode() ?: 0)
        result = 31 * result + (networkV6?.hashCode() ?: 0)
        result = 31 * result + type.hashCode()
        return result
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is IPAddressName) return GeneralNameOption.ConstraintResult.DIFF_TYPE
        if (this == input) return GeneralNameOption.ConstraintResult.MATCH

        if ((address is IpAddress.V4 && input.address is IpAddress.V4 && networkV4 == null && input.networkV4 == null) ||
            (address is IpAddress.V6 && input.address is IpAddress.V6 && networkV6 == null && input.networkV6 == null)
        ) {
            return GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        // Subnet vs Subnet
        if (networkV4 != null && input.networkV4 != null) {
            val thisNet = networkV4
            val otherNet = input.networkV4
            return when {
                thisNet == otherNet -> GeneralNameOption.ConstraintResult.MATCH
                thisNet.contains(otherNet) -> GeneralNameOption.ConstraintResult.WIDENS
                otherNet.contains(thisNet) -> GeneralNameOption.ConstraintResult.NARROWS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }
        if (networkV6 != null && input.networkV6 != null) {
            val thisNet = networkV6
            val otherNet = input.networkV6
            return when {
                thisNet == otherNet -> GeneralNameOption.ConstraintResult.MATCH
                thisNet.contains(otherNet) -> GeneralNameOption.ConstraintResult.WIDENS
                otherNet.contains(thisNet) -> GeneralNameOption.ConstraintResult.NARROWS
                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }

        // Other is subnet, this is host
        if (networkV4 != null && input.address is IpAddress.V4) {
            return if (networkV4.contains(input.address))
                GeneralNameOption.ConstraintResult.NARROWS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }
        if (networkV6 != null && input.address is IpAddress.V6) {
            return if (networkV6.contains(input.address))
                GeneralNameOption.ConstraintResult.NARROWS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        // This is subnet, other is host
        if (input.networkV4 != null && address is IpAddress.V4) {
            return if (input.networkV4.contains(address))
                GeneralNameOption.ConstraintResult.WIDENS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }
        if (input.networkV6 != null && address is IpAddress.V6) {
            return if (input.networkV6.contains(address))
                GeneralNameOption.ConstraintResult.WIDENS
            else GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        return GeneralNameOption.ConstraintResult.SAME_TYPE
    }
}
