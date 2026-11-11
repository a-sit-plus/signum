package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.runRethrowing
import com.eygraber.uri.Uri
import kotlinx.io.IOException

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
