package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Primitive
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.decodeToIa5String
import at.asitplus.signum.indispensable.asn1.runRethrowing
import kotlinx.io.IOException

class UriName(
    val host: Asn1String.IA5,
    val hostDNS: DNSName? = null,
    val hostIP: IPAddressName? = null,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.URI,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {


    override fun encodeToTlv() = host.encodeToTlv()

    companion object : Asn1Decodable<Asn1Primitive, UriName> {

        private val tag: Asn1Element.Tag = Asn1Element.Tag(6u, false)

        override fun doDecode(src: Asn1Primitive): UriName {
            return runRethrowing {
                fromString(src.decodeToIa5String(tag).value)
            }
        }

        private fun fromString(name: String, allowWildcard: Boolean = false): UriName {
            if (name.isEmpty()) throw IOException("URI name cannot be empty")

            val schemeEnd = name.indexOf(':')

            if (schemeEnd <= 0) {
                val normalized = name.removePrefix(".")
                val hostDNS = try {
                    DNSName(Asn1String.IA5(normalized), allowWildcard)
                } catch (e: IOException) {
                    throw IOException("Invalid URI name constraint: $name", e)
                }
                return UriName(Asn1String.IA5(name), hostDNS, null)
            }

            val afterScheme = name.substring(schemeEnd + 1)
            val host = extractHost(afterScheme) ?: return UriName(Asn1String.IA5(name))

            return when {
                host.startsWith("[") && host.endsWith("]") -> {
                    val ipv6 = host.drop(1).dropLast(1)
                    val hostIP = try {
                        IPAddressName.fromString(ipv6)
                    } catch (_: IOException) {
                        throw IOException("Invalid URI name: host portion is not a valid IPv6 address: $name")
                    }
                    UriName(Asn1String.IA5(name), hostIP = hostIP)
                }
                else -> {
                    val hostDNS = runCatching {
                        DNSName(Asn1String.IA5(host), allowWildcard)
                    }.getOrNull()

                    val hostIP = hostDNS?.let { null } ?: runCatching {
                        IPAddressName.fromString(host)
                    }.getOrElse {
                        throw IOException("Invalid URI name: host is not a valid DNS, IPv4, or IPv6 address: $name")
                    }

                    UriName(Asn1String.IA5(name), hostDNS, hostIP)
                }
            }
        }

        private fun extractHost(uriRemainder: String): String? {
            if (!uriRemainder.startsWith("//")) return null

            val withoutScheme = uriRemainder.removePrefix("//")
            val endIndex = withoutScheme.indexOfAny(charArrayOf('/', '?', '#')).let {
                if (it == -1) withoutScheme.length else it
            }

            val authority = withoutScheme.substring(0, endIndex)
            val hostPort = authority.substringAfterLast('@', authority)
            return hostPort.substringBefore(':') //port
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