package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.cidre.IpAddress
import at.asitplus.awesn1.Asn1Exception
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.runRethrowing

/** RFC 5280 `dNSName` GeneralName CHOICE `[2]`. */
class DNSName(
    val value: String,
    val allowWildcard: Boolean = true,
) : AbstractGeneralName() {
    override val equalityValue get() = value

    init {
        if (!value.all { it.code < 128 } || !validate(value, allowWildcard)) throw Asn1Exception("Invalid DNSName.")
    }

    override fun toString(): String = value

    companion object {
        operator fun invoke(value: Asn1String.IA5, allowWildcard: Boolean = true): DNSName =
            DNSName(value.value, allowWildcard)

        val tag = X509GeneralName.Tags.dnsName

        internal fun fromAsn1Model(src: X509GeneralName): DNSName = runRethrowing {
            DNSName((src as X509GeneralName.Dns).value, allowWildcard = true)
        }

        private fun validate(value: String, allowWildcard: Boolean): Boolean {
            if (value.isEmpty() || value.contains(' ') || value.startsWith('.') || value.endsWith('.')) return false

            // check if ip address is encoded as DNSName
            if (value.contains(':')) return false
            if (runCatching { IpAddress(value) }.isSuccess) return false

            var startIndex = 0
            while (startIndex < value.length) {
                val endIndex = value.indexOf('.', startIndex).let { if (it == -1) value.length else it }
                if (endIndex - startIndex < 1) return false

                val firstChar = value[startIndex]

                if (allowWildcard && startIndex == 0 && !firstChar.isLetterOrDigit()) {
                    if (
                        value.length < 3 ||
                        value.indexOf('*') != 0 ||
                        value.getOrNull(startIndex + 1) != '.' ||
                        value.getOrNull(startIndex + 2)?.let { !it.isLetterOrDigit() || it.code >= 128 } == true
                    ) return false
                } else if (!firstChar.isLetterOrDigit()) {
                    return false
                }

                for (i in (startIndex + 1) until endIndex) {
                    val c = value[i]
                    if (!c.isLetterOrDigit() && c != '-') return false
                }

                startIndex = endIndex + 1
            }

            return true
        }
    }
}
