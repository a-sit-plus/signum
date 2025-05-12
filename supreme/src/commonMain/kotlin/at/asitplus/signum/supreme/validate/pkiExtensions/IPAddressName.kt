package at.asitplus.signum.supreme.validate.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1OctetString
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import kotlinx.io.IOException

class IPAddressName(
    val address: Asn1OctetString,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.IP
) : GeneralNameOption, Asn1Encodable<Asn1Element> {

    val isIPv4: Boolean = when (address.content.size) {
        4, 8 -> true
        16, 32 -> false
        else -> throw IOException("Invalid IPAddressName")
    }

    override fun encodeToTlv() = Asn1.OctetString(address.content)

    companion object : Asn1Decodable<Asn1Element, IPAddressName> {
        override fun doDecode(src: Asn1Element): IPAddressName {
            val address = src.asOctetString()
            return IPAddressName(address)
        }

        fun fromString(name: String): IPAddressName {
            if (name.isEmpty()) throw IOException("IPAddress cannot be empty")
            if (name.endsWith('/')) throw IOException("Invalid IPAddress: $name")

            val bytes = when {
                ':' in name -> parseIPv6(name)
                '.' in name -> parseIPv4(name)
                else -> throw IOException("Invalid IPAddress: $name")
            }

            return IPAddressName(Asn1OctetString(bytes))
        }

    }

    override fun constraints(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is IPAddressName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        }

        if (this == input) {
            return GeneralNameOption.ConstraintResult.MATCH
        }

        val thisAddress = address.content
        val inputAddress = input.address.content

        return when {
            isHostAddressMatch(thisAddress, inputAddress) -> GeneralNameOption.ConstraintResult.SAME_TYPE
            isSubnetAddressMatch(thisAddress, inputAddress) -> compareSubnets(thisAddress, inputAddress)
            isHostAndSubnetMatch(thisAddress, inputAddress) -> compareHostAndSubnet(thisAddress, inputAddress)
            isSubnetAndHostMatch(thisAddress, inputAddress) -> compareHostAndSubnet(inputAddress, thisAddress)
            else -> GeneralNameOption.ConstraintResult.SAME_TYPE
        }
    }

    private fun isHostAddressMatch(thisAddress: ByteArray, inputAddress: ByteArray): Boolean {
        return (thisAddress.size == 4 && inputAddress.size == 4) || (thisAddress.size == 16 && inputAddress.size == 16)
    }

    private fun isSubnetAddressMatch(thisAddress: ByteArray, inputAddress: ByteArray): Boolean {
        return (thisAddress.size == 8 && inputAddress.size == 8) || (thisAddress.size == 32 && inputAddress.size == 32)
    }

    private fun isHostAndSubnetMatch(thisAddress: ByteArray, inputAddress: ByteArray): Boolean {
        return (thisAddress.size == 4 && inputAddress.size == 8) || (thisAddress.size == 16 && inputAddress.size == 32)
    }

    private fun isSubnetAndHostMatch(thisAddress: ByteArray, inputAddress: ByteArray): Boolean {
        return (thisAddress.size == 8 && inputAddress.size == 4) || (thisAddress.size == 32 && inputAddress.size == 16)
    }

    private fun compareSubnets(thisAddress: ByteArray, inputAddress: ByteArray): GeneralNameOption.ConstraintResult {
        val maskOffset = thisAddress.size / 2
        var inputSubsetOfThis = true
        var thisSubsetOfInput = true
        var thisEmpty = false
        var inputEmpty = false

        for (i in 0 until maskOffset) {
            if ((thisAddress[i].toInt() and thisAddress[i + maskOffset].toInt()) != thisAddress[i].toInt()) thisEmpty = true
            if ((inputAddress[i].toInt() and inputAddress[i + maskOffset].toInt()) != inputAddress[i].toInt()) inputEmpty = true

            if (!((thisAddress[i + maskOffset].toInt() and inputAddress[i + maskOffset].toInt()) == thisAddress[i + maskOffset].toInt() &&
                        (thisAddress[i].toInt() and thisAddress[i + maskOffset].toInt()) == (inputAddress[i].toInt() and thisAddress[i + maskOffset].toInt()))) {
                inputSubsetOfThis = false
            }

            if (!((inputAddress[i + maskOffset].toInt() and thisAddress[i + maskOffset].toInt()) == inputAddress[i + maskOffset].toInt() &&
                        (inputAddress[i].toInt() and inputAddress[i + maskOffset].toInt()) == (thisAddress[i].toInt() and inputAddress[i + maskOffset].toInt()))) {
                thisSubsetOfInput = false
            }
        }

        return when {
            thisEmpty && inputEmpty -> GeneralNameOption.ConstraintResult.MATCH
            thisEmpty -> GeneralNameOption.ConstraintResult.WIDENS
            inputEmpty -> GeneralNameOption.ConstraintResult.NARROWS
            inputSubsetOfThis -> GeneralNameOption.ConstraintResult.NARROWS
            thisSubsetOfInput -> GeneralNameOption.ConstraintResult.WIDENS
            else -> GeneralNameOption.ConstraintResult.SAME_TYPE
        }
    }

    private fun compareHostAndSubnet(thisAddress: ByteArray, inputAddress: ByteArray): GeneralNameOption.ConstraintResult {
        val maskOffset = inputAddress.size / 2
        val match = (0 until maskOffset).all { i ->
            (thisAddress[i].toInt() and inputAddress[i + maskOffset].toInt()) == inputAddress[i].toInt()
        }
        return if (match) GeneralNameOption.ConstraintResult.WIDENS
        else GeneralNameOption.ConstraintResult.SAME_TYPE
    }
}


@Throws(IOException::class)
fun parseIPv4(name: String): ByteArray {
    val slashIndex = name.indexOf('/')

    return if (slashIndex == -1) {
        // Just a host address
        parseIPv4Address(name)
    } else {
        // Host + subnet mask
        val hostPart = name.substring(0, slashIndex)
        val maskPart = name.substring(slashIndex + 1)

        val host = parseIPv4Address(hostPart)
        val mask = parseIPv4Address(maskPart)

        if (host.size != 4 || mask.size != 4) {
            throw IOException("Invalid IPv4 address or mask: $name")
        }

        ByteArray(8).also { result ->
            host.copyInto(result, 0, 0, 4)
            mask.copyInto(result, 4, 0, 4)
        }
    }
}

@Throws(IOException::class)
private fun parseIPv4Address(input: String): ByteArray {
    val parts = input.split('.')
    if (parts.size != 4) {
        throw IOException("Invalid IPv4 address: $input")
    }

    return ByteArray(4) { index ->
        val value = parts[index].toIntOrNull()
        if (value == null || value !in 0..255) {
            throw IOException("Invalid IPv4 byte '${parts[index]}' in address: $input")
        }
        value.toByte()
    }
}

fun parseIPv6(name: String): ByteArray {
    val slashIndex = name.indexOf('/')
    return if (slashIndex == -1) {
        // No prefix length specified, just parse the address
        parseIPv6Address(name)
    } else {
        // Parse the base address and prefix length
        val baseAddress = parseIPv6Address(name.substring(0, slashIndex))
        val prefixLength = name.substring(slashIndex + 1).toIntOrNull()
            ?: throw IOException("Invalid prefix length for IPv6 address")

        if (prefixLength < 0 || prefixLength > 128) {
            throw IOException("IPv6 address prefix length out of valid range [0, 128]")
        }

        // Combine base address and generated mask
        baseAddress + generateIPv6Mask(prefixLength)
    }
}

private fun parseIPv6Address(address: String): ByteArray {
    val parts = address.split("::")
    if (parts.size > 2) throw IOException("Invalid IPv6 address: too many '::'")

    val headSegments = if (parts[0].isNotEmpty()) parts[0].split(":") else emptyList()
    val tailSegments = if (parts.size == 2 && parts[1].isNotEmpty()) parts[1].split(":") else emptyList()

    val totalSegments = headSegments.size + tailSegments.size
    if (totalSegments > 8) throw IOException("Invalid IPv6 address: too many segments")

    val result = ByteArray(16)
    var byteIndex = 0

    // Process head
    for (segment in headSegments) {
        val value = segment.toUShort(16)
        result[byteIndex++] = (value.toInt() shr 8).toByte()
        result[byteIndex++] = value.toByte()
    }

    // Insert zeros if "::" was present
    val zerosToInsert = 8 - totalSegments
    repeat(zerosToInsert) {
        result[byteIndex++] = 0
        result[byteIndex++] = 0
    }

    // Process tail
    for (segment in tailSegments) {
        val value = segment.toUShort(16)
        result[byteIndex++] = (value.toInt() shr 8).toByte()
        result[byteIndex++] = value.toByte()
    }

    return result
}


private fun generateIPv6Mask(prefixLength: Int): ByteArray {
    val mask = ByteArray(16) { 0 }
    val fullBytes = prefixLength / 8
    val remainingBits = prefixLength % 8

    // Set full bytes to 0xFF
    for (i in 0 until fullBytes) {
        mask[i] = 0xFF.toByte()
    }

    // Set the remaining bits in the last byte
    if (remainingBits > 0) {
        mask[fullBytes] = (0xFF shr (8 - remainingBits)).toByte()
    }

    return mask
}
