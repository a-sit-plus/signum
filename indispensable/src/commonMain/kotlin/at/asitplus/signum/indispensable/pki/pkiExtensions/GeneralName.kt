package at.asitplus.signum.indispensable.pki.pkiExtensions

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception

interface GeneralNameOption {

    enum class NameType(val value: ULong) {
        OTHER(0u), RFC822(1u), DNS(2u), X400(3u), DIRECTORY(4u), EDI(5u), URI(6u), IP(7u), OID(8u);

        companion object {
            fun fromTagValue(tagValue: ULong): NameType? =
                NameType.entries.firstOrNull { it.value == tagValue }
        }
    }

    enum class ConstraintResult {
        DIFF_TYPE,     // Different type, no constraint
        MATCH,         // Exact match
        NARROWS,       // Input narrows this name
        WIDENS,        // Input widens this name
        SAME_TYPE;      // Same type, but no match/narrow/widen
    }

    val type: NameType

    fun constrains(input: GeneralNameOption?): ConstraintResult
}

data class GeneralName(
    val name: GeneralNameOption
) : Asn1Encodable<Asn1Element> {
    override fun encodeToTlv(): Asn1Element {
        return when (name.type) {
            GeneralNameOption.NameType.RFC822 -> (name as RFC822Name).encodeToTlv()
            GeneralNameOption.NameType.DNS -> (name as DNSName).encodeToTlv()
            GeneralNameOption.NameType.IP -> (name as IPAddressName).encodeToTlv()
            GeneralNameOption.NameType.X400 -> (name as X400AddressName).encodeToTlv()
            GeneralNameOption.NameType.URI -> (name as UriName).encodeToTlv()
            GeneralNameOption.NameType.DIRECTORY -> (name as X500Name).encodeToTlv()
            GeneralNameOption.NameType.OTHER -> (name as OtherName).encodeToTlv()
            GeneralNameOption.NameType.EDI -> (name as EDIPartyName).encodeToTlv()
            GeneralNameOption.NameType.OID -> (name as RegisteredIDName).encodeToTlv()
        }
    }

    companion object : Asn1Decodable<Asn1Element, GeneralName> {
        override fun doDecode(src: Asn1Element): GeneralName {
            return when (GeneralNameOption.NameType.fromTagValue(src.tag.tagValue)) {
                GeneralNameOption.NameType.OTHER -> GeneralName(OtherName.decodeFromTlv(src))
                GeneralNameOption.NameType.RFC822 -> GeneralName(RFC822Name.decodeFromTlv(src.asPrimitive()))
                GeneralNameOption.NameType.DNS -> GeneralName(DNSName.decodeFromTlv(src.asPrimitive()))
                GeneralNameOption.NameType.OID -> GeneralName(RegisteredIDName.decodeFromTlv(src.asPrimitive()))
                GeneralNameOption.NameType.IP -> GeneralName(IPAddressName.decodeFromTlv(src.asPrimitive()))
                GeneralNameOption.NameType.X400 -> GeneralName(X400AddressName.decodeFromTlv(src))
                GeneralNameOption.NameType.URI -> GeneralName(UriName.decodeFromTlv(src.asPrimitive()))
                GeneralNameOption.NameType.EDI -> GeneralName(EDIPartyName.decodeFromTlv(src))
                GeneralNameOption.NameType.DIRECTORY -> GeneralName(
                    X500Name.decodeFromTlv(
                        src.asExplicitlyTagged().single().asSequence()
                    )
                )
                else -> throw Asn1Exception("Unsupported GeneralName tag")
            }
        }
    }

    override fun toString(): String {
        val bld = StringBuilder("\nType=").append(name.type)
        bld.append("\nValue=").append(name.toString())
        return "GeneralName(" + bld.toString().prependIndent("  ") + "\n)"
    }
}




