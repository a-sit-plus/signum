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
import com.eygraber.uri.Uri
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
        if (host.value.isEmpty()) {
            throw IOException("URI name cannot be empty")
        }

        val uri = Uri.parse(host.value)
        val hostStr: String = if (uri.host == null) {
            // No scheme → treat entire value as host
            host.value
        } else {
            uri.host!!
        }

        var tmpHostDNS: DNSName? = null
        var tmpHostIP: IPAddressName? = null

        if (hostStr.startsWith("[") && hostStr.endsWith("]")) {
            // IPv6 in brackets
            val ipv6Host = hostStr.substring(1, hostStr.length - 1)
            tmpHostIP = try {
                IPAddressName.fromString(ipv6Host)
            } catch (e: IOException) {
                throw IOException("Invalid URI name: host portion is not a valid IPv6 address: ${host.value}", e)
            }
        } else {
            // Try DNS first
            tmpHostDNS = try {
                val normalizedHost = if (hostStr.startsWith(".")) hostStr.substring(1) else hostStr
                DNSName(Asn1String.IA5(normalizedHost), allowWildcard)
            } catch (_: IOException) {
                null
            }

            // If not DNS, try IP
            if (tmpHostDNS == null) {
                tmpHostIP = try {
                    IPAddressName.fromString(hostStr)
                } catch (e: IOException) {
                    throw IOException(
                        "Invalid URI name: host is not a valid DNS, IPv4, or IPv6 address: ${host.value}", e
                    )
                }
            }
        }

        hostDNS = tmpHostDNS
        hostIP = tmpHostIP
        isValid = hostDNS != null || hostIP != null

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