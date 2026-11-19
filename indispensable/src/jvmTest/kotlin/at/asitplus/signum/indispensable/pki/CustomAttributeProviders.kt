package at.asitplus.signum.indispensable.pki

import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X500AttributeTypeAndValue
import at.asitplus.signum.indispensable.pki.AttributeTypeAndValueProvider.*

internal class Nickname(value: String) : TextAttributeTypeAndValue(Companion.oid, value) {
    companion object { val oid = ObjectIdentifier("1.2.3.1234567890") }
}

internal class NicknameProvider(private val alias: String, private val strict: Boolean) :
    AttributeTypeAndValueProvider, AttributeTypeAndValueAsn1Provider {

    private val oidKey = Key(Nickname.oid)

    override fun decodeATV(key: Key, value: Value): AttributeTypeAndValue? {
        if (key != oidKey && key != Key(alias) && key != Key("NICK") && key != Key("NICKNAME")) return null
        return when (value) {
            is StringValue -> nickname(value.str)
            is ByteArrayValue -> AtvAsn1FallbackProvider.decodeATV(oidKey, value)
        }
    }

    override fun encodeATV(atv: AttributeTypeAndValue): Pair<Key, Value>? =
        if (atv is Nickname) Key(alias) to Value(atv.text) else null

    override fun decodeFromAsn1(value: X500AttributeTypeAndValue): AttributeTypeAndValue? {
        if (value.oid != Nickname.oid) return null
        val text = Asn1String.decodeFromTlv(value.value.asPrimitive())
        require(text.isValid != false) { "Malformed nickname string" }
        return nickname(text.value)
    }

    override fun encodeToAsn1(value: AttributeTypeAndValue): X500AttributeTypeAndValue? =
        if (value is Nickname) X500AttributeTypeAndValue(value.oid, Asn1String.UTF8(value.text)) else null

    private fun nickname(text: String): Nickname {
        require(text.isNotEmpty()) { "Nickname cannot be empty" }
        val lowercase = text.lowercase()
        require(!strict || text == lowercase) { "Nickname must be lowercase" }
        return Nickname(lowercase)
    }
}
