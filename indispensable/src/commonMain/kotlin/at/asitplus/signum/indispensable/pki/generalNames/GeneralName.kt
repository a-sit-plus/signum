package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.signum.indispensable.asn1.Asn1Decodable
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1Encodable
import at.asitplus.signum.indispensable.asn1.Asn1Exception

sealed interface GeneralNameOption {

    /**
     * Returns whether this name is valid:
     * - `true`: validation succeeded
     * - `false`: validation failed
     * - `null`: no validation implemented
     */
    val isValid: Boolean?

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
        SAME_TYPE;     // Same type, but no match/narrow/widen
    }

    val type: NameType

    fun constrains(input: GeneralNameOption?): ConstraintResult {
        when {
            input == null || this::class != input::class -> return ConstraintResult.DIFF_TYPE

            isValid == null || input.isValid == null ->
                throw IllegalArgumentException(
                    "${this::class.simpleName} does not support validation out of the box. " +
                            "You must explicitly provide custom validation logic using " +
                            "${this::class.simpleName}.createValidatedCopy { /* validation logic */ } before calling constrains."
                )

            !isValid!! || !input.isValid!! -> {
                throw Asn1Exception("Invalid ${this::class.simpleName}")
            }

            else -> throw UnsupportedOperationException(
                "Narrows, widens and match are not yet implemented for ${this::class.simpleName}."
            )
        }
    }

    /**
     * Returns a copy of this GeneralNameOption with the `isValid` property set
     * according to the [validate] lambda.
     *
     * Intended for subclasses that do not implement validation (`isValid == null`)
     * and allows marking them as valid or invalid before performing constraint checks.
     */
    fun createValidatedCopy(validate: (GeneralNameOption) -> Boolean) : GeneralNameOption {
        throw IllegalArgumentException()
    }
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
                        src.asExplicitlyTagged().children.first().asSequence()
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




