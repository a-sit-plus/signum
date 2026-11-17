package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.ObjectIdentifier

internal class Nickname(value: String) : TextAttributeTypeAndValue(Companion.oid, value) {
    companion object { val oid = ObjectIdentifier("1.2.3.1234567890") }
}

internal object LenientNicknameProvider : AttributeTypeAndValueProvider {
    override fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? =
        if (oid == Nickname.oid) ({
            require(it.isNotEmpty()) { "Nickname cannot be empty" }
            Nickname(it.lowercase())
        }) else null

    override fun nameForOid(oid: ObjectIdentifier): String? = "LEGACYNICK".takeIf { oid == Nickname.oid }
}

internal object NicknameProvider : AttributeTypeAndValueProvider {
    override fun decoderFor(oid: ObjectIdentifier): ((String) -> AttributeTypeAndValue)? =
        if (oid == Nickname.oid) ({
            require(it.isNotEmpty()) { "Nickname cannot be empty" }
            require(it == it.lowercase()) { "Nickname must be lowercase" }
            Nickname(it)
        }) else null

    override fun oidForName(name: String): ObjectIdentifier? =
        Nickname.oid.takeIf { name == "NICK" || name == "NICKNAME" }

    override fun nameForOid(oid: ObjectIdentifier): String? = "NICK".takeIf { oid == Nickname.oid }
}
