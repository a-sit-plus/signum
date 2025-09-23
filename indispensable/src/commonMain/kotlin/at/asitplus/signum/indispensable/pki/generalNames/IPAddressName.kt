package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpAddressAndPrefix
import at.asitplus.cidre.IpInterface
import at.asitplus.cidre.IpNetwork
import at.asitplus.cidre.byteops.toPrefix
import at.asitplus.cidre.isV4
import at.asitplus.cidre.isV6
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive
import kotlinx.io.IOException

data class IPAddressName(
    val address: IpAddress<*, *>,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    override val performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.IP
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    /**
     * Always `null`, since no validation logic is implemented
     */
    override val isValid: Boolean? = null

    val network: IpNetwork<*, *>? by lazy {
        when (addressAndPrefix) {
            is IpInterface<*, *> -> addressAndPrefix.network
            is IpNetwork<*, *> -> addressAndPrefix
            else -> null
        }
    }

    override fun encodeToTlv(): Asn1Primitive {
        //TODO change after CIDRE update
        val bytes = addressAndPrefix?.let { it.address.octets + it.netmask } ?: address.octets
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
        //TODO change after CIDRE update
        private fun createNetworkV4(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V4(bytes.copyOfRange(0, 4))
            val prefix = bytes.copyOfRange(4, 8).toPrefix()
            return IPAddressName(address, addressAndPrefix = IpInterface.V4(address, prefix))
        }
        //TODO change after CIDRE update
        private fun createNetworkV6(bytes: ByteArray): IPAddressName {
            val address = IpAddress.V6(bytes.copyOfRange(0, 16))
            val prefix = bytes.copyOfRange(16, 32).toPrefix()
            return IPAddressName(address, addressAndPrefix = IpInterface.V6(address, prefix))
        }

        fun fromString(name: String): IPAddressName =
            runCatching { IpInterface(name) }
                .map { IPAddressName(it.address, it) }
                .getOrElse { IPAddressName(IpAddress(name)) }
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
        result = 31 * result + (isValid?.hashCode() ?: 0)
        result = 31 * result + address.hashCode()
        result = 31 * result + (addressAndPrefix?.hashCode() ?: 0)
        result = 31 * result + type.hashCode()
        return result
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is IPAddressName) return GeneralNameOption.ConstraintResult.DIFF_TYPE
        if (this == input) return GeneralNameOption.ConstraintResult.MATCH

        if (network == null && input.network == null &&
            ((address.isV4() && input.address.isV4()) || (address.isV6() && input.address.isV6()))) {
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
