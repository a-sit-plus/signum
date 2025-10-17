package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpAddressAndPrefix
import at.asitplus.cidre.IpFamily
import at.asitplus.cidre.IpInterface
import at.asitplus.cidre.IpNetwork
import at.asitplus.cidre.isV4
import at.asitplus.cidre.isV6
import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.encoding.encodeToAsn1OctetStringPrimitive

class IPAddressName internal constructor(
    val address: IpAddress<*, *>?,
    val addressAndPrefix: IpAddressAndPrefix<*, *>? = null,
    val rawBytes: ByteArray,
    performValidation: Boolean,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.IP
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

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

    override fun encodeToTlv(): Asn1Primitive {
        return rawBytes.encodeToAsn1OctetStringPrimitive()
    }

    companion object : Asn1Decodable<Asn1Primitive, IPAddressName> {

        override fun doDecode(src: Asn1Primitive): IPAddressName {
            val content = src.content
            return when (content.size) {
                IpFamily.V4.numberOfOctets -> IPAddressName(
                    IpAddress.V4(content), rawBytes = IpAddress.V4(content).octets, performValidation = false
                )

                IpFamily.V6.numberOfOctets -> IPAddressName(
                    IpAddress.V6(content), rawBytes = IpAddress.V6(content).octets, performValidation = false
                )

                else -> {
                    val addressAndPrefix = IpInterface.fromX509Octets(content)
                    IPAddressName(addressAndPrefix)
                }
            }
        }

        /**
         * @throws IllegalArgumentException if an invalid string is provided
         * @throws Asn1Exception if an invalid [address] is provided
         * */
        @Throws(Asn1Exception::class, IllegalArgumentException::class)
        fun fromString(stringRepresentation: String): IPAddressName = runCatching {
            IPAddressName(IpInterface(stringRepresentation))
        }.getOrElse {
            IPAddressName(IpAddress(stringRepresentation))
        }
    }

    override fun toString(): String = addressAndPrefix?.toString() ?: address.toString()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as IPAddressName

        if (isValid != other.isValid) return false
        if (address != other.address) return false
        if (addressAndPrefix != other.addressAndPrefix) return false
        if (!rawBytes.contentEquals(other.rawBytes)) return false
        if (type != other.type) return false
        if (network != other.network) return false

        return true
    }

    override fun hashCode(): Int {
        var result = isValid.hashCode()
        result = 31 * result + (address?.hashCode() ?: 0)
        result = 31 * result + (addressAndPrefix?.hashCode() ?: 0)
        result = 31 * result + rawBytes.contentHashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + (network?.hashCode() ?: 0)
        return result
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            when {
                this == input as IPAddressName -> GeneralNameOption.ConstraintResult.MATCH

                network == null && input.network == null &&
                        ((address!!.isV4() && input.address!!.isV4()) || (address!!.isV6() && input.address!!.isV6())) ->
                    GeneralNameOption.ConstraintResult.SAME_TYPE

                network != null && input.network != null -> {
                    val thisNet = network as IpNetwork<Number, Any>
                    val otherNet = input.network as IpNetwork<Number, Any>
                    when {
                        thisNet == otherNet -> GeneralNameOption.ConstraintResult.MATCH
                        thisNet.contains(otherNet) -> GeneralNameOption.ConstraintResult.WIDENS
                        otherNet.contains(thisNet) -> GeneralNameOption.ConstraintResult.NARROWS
                        else -> GeneralNameOption.ConstraintResult.SAME_TYPE
                    }
                }

                network != null -> {
                    val thisNet = network as IpNetwork<Number, Any>
                    val otherAddress = input.address as IpAddress<Number, Any>
                    if (thisNet.contains(otherAddress)) GeneralNameOption.ConstraintResult.WIDENS
                    else GeneralNameOption.ConstraintResult.SAME_TYPE
                }

                input.network != null -> {
                    val thisAddress = address as IpAddress<Number, Any>
                    val otherNet = input.network as IpNetwork<Number, Any>
                    if (otherNet.contains(thisAddress)) GeneralNameOption.ConstraintResult.NARROWS
                    else GeneralNameOption.ConstraintResult.SAME_TYPE
                }

                else -> GeneralNameOption.ConstraintResult.SAME_TYPE
            }
        }
    }
}
