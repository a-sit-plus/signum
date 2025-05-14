package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String
import kotlinx.io.IOException

class UriName(
    val host: Asn1String.IA5,
    val hostDNS: DNSName? = null,
    val hostIP: IPAddressName? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.URI,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {


    override fun encodeToTlv() = host.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, UriName> {
        override fun doDecode(src: Asn1Primitive): UriName {
            return fromString(src.asAsn1String().value)
        }

        private fun fromString(name: String, allowWildcard: Boolean = false): UriName {
            if (name.isEmpty()) throw IOException("URI name cannot be empty")

            val schemeEnd = name.indexOf(':')
            if (schemeEnd <= 0) throw IOException("URI name must include scheme: $name")

            val afterScheme = name.substring(schemeEnd + 1)
            val host: String? = extractHost(afterScheme)
            var hostIP: IPAddressName? = null
            var hostDNS: DNSName? = null

            if (host != null) {
                if (host.startsWith("[") && host.endsWith("]")) {
                    val ipv6Host = host.substring(1, host.length - 1)
                    hostIP = try {
                        IPAddressName.fromString(ipv6Host)
                    } catch (e: IOException) {
                        throw IOException("Invalid URI name: host portion is not a valid IPv6 address: $name")
                    }
                } else {
                    hostDNS = try {
                        DNSName(Asn1String.IA5(host), allowWildcard)
                    } catch (_: IOException) {
                        null
                    }

                    hostIP = if (hostDNS == null) {
                        try {
                            IPAddressName.fromString(host)
                        } catch (_: IOException) {
                            throw IOException("Invalid URI name: host is not a valid DNS, IPv4, or IPv6 address: $name")
                        }
                    } else null
                }
            }

            return UriName(Asn1String.IA5(name), hostDNS, hostIP)
        }

        private fun extractHost(uriRemainder: String): String? {
            if (!uriRemainder.startsWith("//")) return null

            val withoutScheme = uriRemainder.removePrefix("//")
            val endIndex = withoutScheme.indexOfAny(charArrayOf('/', '?', '#')).let {
                if (it == -1) withoutScheme.length else it
            }

            val authority = withoutScheme.substring(0, endIndex)
            val atIndex = authority.lastIndexOf('@')
            return if (atIndex >= 0) authority.substring(atIndex + 1) else authority
        }
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

        val thisDNS = this.hostDNS
        val inputHostObject = input.hostDNS ?: input.hostIP

        if (thisDNS == null || inputHostObject !is DNSName) {
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