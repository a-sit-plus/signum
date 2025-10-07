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

class UriName internal constructor(
    val host: Asn1String.IA5,
    val allowWildcard: Boolean = false,
    performValidation: Boolean = false,
    override val type: GeneralNameOption.NameType = GeneralNameOption.NameType.URI,
) : GeneralNameOption, Asn1Encodable<Asn1Primitive> {

    val hostDNS: DNSName?
    val hostIP: IPAddressName?

    override val isValid: Boolean

    @Throws(Asn1Exception::class)
    constructor(value: String, allowWildcard: Boolean = false) : this(Asn1String.IA5(value), allowWildcard, true)

    init {
        if (performValidation && host.value.isEmpty()) {
            throw IOException("URI name cannot be empty")
        }

        val hostStr = Uri.parse(host.value).host ?: host.value

        val (tmpHostDNS, tmpHostIP) = when {
            hostStr.startsWith("[") && hostStr.endsWith("]") -> {
                // IPv6 in brackets
                val ipv6Host = hostStr.removePrefix("[").removeSuffix("]")
                null to runCatching { IPAddressName.fromString(ipv6Host) }.getOrNull()
            }
            else -> {
                // Try DNS first
                val normalizedHost = hostStr.removePrefix(".")
                val dns = runCatching { DNSName(Asn1String.IA5(normalizedHost), allowWildcard) }.getOrNull()

                val ip = if (dns == null) runCatching { IPAddressName.fromString(hostStr) }.getOrNull() else null
                dns to ip
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
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val inputHost = (input as UriName).host.value.lowercase()
            val thisHost = host.value.lowercase()

            when {
                thisHost == inputHost -> GeneralNameOption.ConstraintResult.MATCH

                hostDNS == null || input.hostDNS == null -> GeneralNameOption.ConstraintResult.SAME_TYPE

                else -> {
                    val thisDomain = thisHost.startsWith('.')
                    val otherDomain = inputHost.startsWith('.')
                    var constraintResult = hostDNS.constrains(input.hostDNS)

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

                    constraintResult
                }
            }
        }
    }
}