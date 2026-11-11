package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.indispensable.fromAsn1
import at.asitplus.signum.indispensable.pki.Name

/**
 * RFC 5280 `directoryName` GeneralName CHOICE `[4] EXPLICIT`. Wraps a core [Name] so the
 * GeneralName CHOICE machinery stays out of the lean core.
 */
class DirectoryName(
    val name: Name,
) : AbstractGeneralName() {
    override val equalityValue get() = name

    override fun toString(): String = name.toString()

    companion object {
        val tag = X509GeneralName.Tags.directoryName

        internal fun fromAsn1Model(src: X509GeneralName): DirectoryName {
            val awesnName = (src as X509GeneralName.Directory).value
            return DirectoryName(Name.fromAsn1(awesnName))
        }
    }
}
