package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.Signum
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.pki.x500.*

/** ASN.1 adapters for the open OtherName family, selected by its inner OID. */
interface OtherNameAsn1Provider {
    fun decodeFromAsn1(value: X509GeneralName.Other): OtherName?
    fun encodeToAsn1(value: OtherName): X509GeneralName.Other?
}

internal fun decodeOtherName(src: X509GeneralName.Other): OtherName = try {
    ServiceLoader.load<OtherNameAsn1Provider>().get(src, OtherNameAsn1Provider::decodeFromAsn1)
} catch (failure: UnsupportedCryptoException) {
    OtherName(src.value.oid, failure)
}

internal fun encodeOtherName(src: OtherName): X509GeneralName.Other =
    ServiceLoader.load<OtherNameAsn1Provider>().get(src, OtherNameAsn1Provider::encodeToAsn1)

internal object BuiltinOtherNames : OtherNameAsn1Provider {
    override fun decodeFromAsn1(value: X509GeneralName.Other): OtherName? {
        val raw = value.value as? X509GeneralName.Other.SemanticValue.Generic ?: return null
        return when (raw.oid) {
            HardwareModuleName.OID -> Signum.Der.decodeFromTlv(HardwareModuleName.Asn1Representation.serializer(), raw.value).let {
                HardwareModuleName(it.hardwareType, it.serial)
            }
            SmtpUtf8Mailbox.OID -> SmtpUtf8Mailbox(Signum.Der.decodeFromTlv(Asn1String.UTF8.serializer(), raw.value).value)
            MacAddressName.OID -> MacAddressName(Signum.Der.decodeFromTlv(kotlinx.serialization.builtins.ByteArraySerializer(), raw.value))
            else -> null
        }
    }

    override fun encodeToAsn1(value: OtherName): X509GeneralName.Other? {
        val payload = when (value) {
            is HardwareModuleName -> Signum.Der.encodeToTlv(HardwareModuleName.Asn1Representation.serializer(), HardwareModuleName.Asn1Representation(value.hardwareType, value.serial))
            is SmtpUtf8Mailbox -> Signum.Der.encodeToTlv(Asn1String.UTF8.serializer(), Asn1String.UTF8(value.address))
            is MacAddressName -> Signum.Der.encodeToTlv(kotlinx.serialization.builtins.ByteArraySerializer(), value.address)
            else -> return null
        }
        return X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(value.oid, payload))
    }
}
