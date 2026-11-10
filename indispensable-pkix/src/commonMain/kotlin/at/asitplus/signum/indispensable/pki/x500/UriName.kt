package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.signum.indispensable.pki.ExperimentalPkiApi
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.runRethrowing
import com.eygraber.uri.Uri
import kotlinx.io.IOException
import at.asitplus.signum.indispensable.pki.GeneralName
import at.asitplus.signum.indispensable.pki.x500.ConstraintResult

/** RFC 5280 `uniformResourceIdentifier` GeneralName CHOICE `[6]`. */
class UriName(
    value: String,
    val allowWildcard: Boolean = false,
) : AbstractGeneralName() {
    val host: String = value
    override val equalityValue get() = host

    val hostDNS: DNSName?
    val hostIP: IPAddressName?

    init {
        if (host.isEmpty()) {
            throw IOException("URI name cannot be empty")
        }

        val hostStr = Uri.parse(host).host ?: host

        val (tmpHostDNS, tmpHostIP) = when {
            hostStr.startsWith("[") && hostStr.endsWith("]") -> {
                // IPv6 in brackets
                val ipv6Host = hostStr.removePrefix("[").removeSuffix("]")
                null to runCatching { IPAddressName.fromString(ipv6Host) }.getOrNull()
            }

            else -> {
                // Try DNS first
                val normalizedHost = hostStr.removePrefix(".")
                val dns = runCatching { DNSName(normalizedHost, allowWildcard) }.getOrNull()
                val ip = if (dns == null) runCatching { IPAddressName.fromString(hostStr) }.getOrNull() else null
                dns to ip
            }
        }

        hostDNS = tmpHostDNS
        hostIP = tmpHostIP
        if (hostDNS == null && hostIP == null) {
            throw Asn1Exception("Invalid URI name: ${host}")
        }
    }

    override fun toString(): String = host

    @ExperimentalPkiApi
    override fun constrains(input: GeneralName?): ConstraintResult {
        return try {
            super.constrains(input)
        } catch (_: UnsupportedOperationException) {
            val inputHost = (input as UriName).host.lowercase()
            val thisHost = host.lowercase()

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

    companion object {
        val tag = X509GeneralName.Tags.uniformResourceIdentifier

        internal fun fromAsn1Model(src: X509GeneralName): UriName = runRethrowing {
            UriName(
                (src as X509GeneralName.UniformResourceIdentifier).value,
                allowWildcard = false,

            )
        }
    }
}
