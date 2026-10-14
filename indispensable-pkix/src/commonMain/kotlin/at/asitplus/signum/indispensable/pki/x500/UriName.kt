package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.runRethrowing
import com.eygraber.uri.Uri
import kotlinx.io.IOException
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.GeneralName.ConstraintResult
import at.asitplus.signum.indispensable.pki.GeneralName.X509Representable.Descriptor

/** RFC 5280 `uniformResourceIdentifier` GeneralName CHOICE `[6]`. */
class UriName private constructor(
    val host: Asn1String.IA5,
    val allowWildcard: Boolean,
    asn1Representation: X509GeneralName,
    performValidation: Boolean,
) : AbstractX509GeneralName(asn1Representation) {

    val hostDNS: DNSName?
    val hostIP: IPAddressName?

    override val isValid: Boolean

    @Throws(Asn1Exception::class)
    constructor(value: String, allowWildcard: Boolean = false)
            : this(Asn1String.IA5(value), allowWildcard, X509GeneralName.UniformResourceIdentifier(value), true)

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

    override fun toString(): String = host.value

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val inputHost = (input as UriName).host.value.lowercase()
            val thisHost = host.value.lowercase()

            when {
                thisHost == inputHost -> ConstraintResult.MATCH

                hostDNS == null || input.hostDNS == null -> ConstraintResult.SAME_TYPE

                else -> {
                    val thisDomain = thisHost.startsWith('.')
                    val otherDomain = inputHost.startsWith('.')
                    var constraintResult = hostDNS.constrains(input.hostDNS)

                    if (!thisDomain && !otherDomain &&
                        (constraintResult == ConstraintResult.WIDENS || constraintResult == ConstraintResult.NARROWS)
                    ) {
                        constraintResult = ConstraintResult.SAME_TYPE
                    }

                    if (constraintResult == ConstraintResult.MATCH && thisDomain != otherDomain) {
                        constraintResult = ConstraintResult.NARROWS
                    }

                    constraintResult
                }
            }
        }
    }

    companion object : Descriptor {
        override val tag = X509GeneralName.Tags.uniformResourceIdentifier

        override fun fromAsn1Representation(src: X509GeneralName): UriName = runRethrowing {
            UriName(
                (src as X509GeneralName.UniformResourceIdentifier).rawValue,
                allowWildcard = false,
                asn1Representation = src,
                performValidation = false,
            )
        }
    }
}
