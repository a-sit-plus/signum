package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.TagClass
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.asn1.runRethrowing
import kotlinx.io.IOException

data class UriName(
    val host: Asn1String.IA5,
    val allowWildcard: Boolean = false,
    override val performValidation: Boolean = true,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.URI,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    val hostDNS: DNSName?
    val hostIP: IPAddressName?

    override val isValid: Boolean

    @Throws(Asn1Exception::class)
    constructor(value: String, allowWildcard: Boolean = false) : this(Asn1String.IA5(value), allowWildcard, true)

    init {
        var dns: DNSName? = null
        var ip: IPAddressName? = null
        var valid = true

        try {
            val hostStr = host.value
            if (hostStr.isEmpty()) throw IOException("URI name cannot be empty")

            val schemeEnd = hostStr.indexOf(':')
            val afterScheme = if (schemeEnd >= 0) hostStr.substring(schemeEnd + 1) else hostStr
            val hostPart = extractHost(afterScheme) ?: afterScheme

            if (hostPart.startsWith("[") && hostPart.endsWith("]")) {
                // IPv6
                val ipv6Host = hostPart.substring(1, hostPart.length - 1)
                ip = IPAddressName.fromString(ipv6Host)
            } else {
                try { dns = DNSName(Asn1String.IA5(hostPart), allowWildcard) } catch (_: IOException) {}
                if (dns == null) {
                    ip = IPAddressName.fromString(hostPart)
                }
            }
        } catch (_: IOException) {
            valid = false
        }

        hostDNS = dns
        hostIP = ip
        isValid = valid

        if (performValidation && !isValid) {
            throw Asn1Exception("Invalid URI name: ${host.value}")
        }
    }

    override fun encodeToTlv() = host.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, UriName> {
        private val tag: Asn1Element.Tag = Asn1Element.Tag(6u, false, TagClass.CONTEXT_SPECIFIC)

        override fun doDecode(src: Asn1Primitive): UriName = runRethrowing {
            UriName(src.decodeToIa5String(tag))
        }

        private fun extractHost(value: String): String? {
            val trimmed = value.trimStart('/')
            val end = trimmed.indexOfAny(charArrayOf('/', '?', '#'))
            return if (end >= 0) trimmed.substring(0, end) else trimmed
        }
    }


    override fun toString(): String {
        return host.value
    }

    override fun constrains(input: GeneralNameOption?): GeneralNameOption.ConstraintResult {
        if (input !is UriName) {
            return GeneralNameOption.ConstraintResult.DIFF_TYPE
        }

        val inputHost = input.host.value.lowercase()
        val thisHost = host.value.lowercase()

        if (thisHost == inputHost) {
            return GeneralNameOption.ConstraintResult.MATCH
        }

        val inputHostObject = input.hostDNS
        val thisDNS = this.hostDNS

        if (thisDNS == null || inputHostObject == null) {
            return GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        val thisDomain = thisHost.startsWith('.')
        val otherDomain = inputHost.startsWith('.')

        var constraintResult = thisDNS.constrains(inputHostObject)

        if (!thisDomain && !otherDomain &&
            (constraintResult == GeneralNameOption.ConstraintResult.WIDENS ||
                    constraintResult == GeneralNameOption.ConstraintResult.NARROWS)
        ) {
            constraintResult = GeneralNameOption.ConstraintResult.SAME_TYPE
        }

        if (constraintResult == GeneralNameOption.ConstraintResult.MATCH && thisDomain != otherDomain) {
            constraintResult = if (thisDomain) {
                GeneralNameOption.ConstraintResult.WIDENS
            } else {
                GeneralNameOption.ConstraintResult.NARROWS
            }
        }

        return constraintResult
    }
}