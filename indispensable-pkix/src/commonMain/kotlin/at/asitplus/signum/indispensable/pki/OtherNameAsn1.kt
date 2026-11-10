package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.*
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.signum.Signum
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.pki.x500.*
import kotlinx.serialization.Serializable

@Serializable
private data class HardwareModuleWire(val hardwareType: ObjectIdentifier, val serial: ByteArray)

internal fun decodeOtherName(src: X509GeneralName.Other): OtherName {
    val raw = src.value as? X509GeneralName.Other.SemanticValue.Generic ?: return OtherName(src.value.oid)
    return at.asitplus.catchingUnwrapped {
        when (raw.oid) {
            HardwareModuleName.OID -> Signum.Der.decodeFromTlv(HardwareModuleWire.serializer(), raw.value).let {
                HardwareModuleName(it.hardwareType, it.serial)
            }
            SmtpUtf8Mailbox.OID -> SmtpUtf8Mailbox(Signum.Der.decodeFromTlv(Asn1String.UTF8.serializer(), raw.value).value)
            MacAddressName.OID -> MacAddressName(Signum.Der.decodeFromTlv(kotlinx.serialization.builtins.ByteArraySerializer(), raw.value))
            else -> OtherName(raw.oid)
        }
    }.getOrElse { failure ->
        OtherName(raw.oid, failure as? UnsupportedCryptoException
            ?: UnsupportedCryptoException("Cannot decode otherName ${raw.oid}", failure))
    }
}

internal fun encodeOtherName(src: OtherName): X509GeneralName.Other? {
    val payload = when (src) {
        is HardwareModuleName -> Signum.Der.encodeToTlv(HardwareModuleWire.serializer(), HardwareModuleWire(src.hardwareType, src.serial))
        is SmtpUtf8Mailbox -> Signum.Der.encodeToTlv(Asn1String.UTF8.serializer(), Asn1String.UTF8(src.address))
        is MacAddressName -> Signum.Der.encodeToTlv(kotlinx.serialization.builtins.ByteArraySerializer(), src.address)
        else -> return null
    }
    return X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(src.oid, payload))
}
