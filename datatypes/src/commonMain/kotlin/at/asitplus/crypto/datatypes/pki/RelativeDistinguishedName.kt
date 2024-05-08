package at.asitplus.crypto.datatypes.pki

import at.asitplus.crypto.datatypes.asn1.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * X.500 Name (used in X.509 Certificates)
 */
@Serializable
data class RelativeDistinguishedName(val attrsAndValues: List<AttributeTypeAndValue>) : Asn1Encodable<Asn1Set> {

    constructor(singleItem: AttributeTypeAndValue) : this(listOf(singleItem))

    override fun encodeToTlv() = runRethrowing {
        asn1Set {
            attrsAndValues.forEach {
                append(it)
            }
        }
    }

    companion object : Asn1Decodable<Asn1Set, RelativeDistinguishedName> {
        override fun decodeFromTlv(src: Asn1Set): RelativeDistinguishedName = runRethrowing {
            RelativeDistinguishedName(src.children.map { AttributeTypeAndValue.decodeFromTlv(it as Asn1Sequence) })
        }
    }

    override fun toString() = "DistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

}

//TODO: value should be Asn1Primitive???
@Serializable
sealed class AttributeTypeAndValue : Asn1Encodable<Asn1Sequence>, Identifiable {
    abstract val value: Asn1Element

    override fun toString() = value.toString()

    @Serializable
    @SerialName("CN")
    class CommonName(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.commonName
        }
    }

    @Serializable
    @SerialName("C")
    class Country(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.countryName
        }
    }

    @Serializable
    @SerialName("O")
    class Organization(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationName
        }
    }

    @Serializable
    @SerialName("OU")
    class OrganizationalUnit(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationalUnitName
        }
    }

    @Serializable
    @SerialName("?")
    class Other(override val oid: ObjectIdentifier, override val value: Asn1Element) : AttributeTypeAndValue() {
        constructor(oid: ObjectIdentifier, str: Asn1String) : this(
            oid,
            Asn1Primitive(str.tag, str.value.encodeToByteArray())
        )
    }

    override fun encodeToTlv() = asn1Sequence {
        append(oid)
        append(value)

    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as AttributeTypeAndValue

        if (value != other.value) return false
        if (oid != other.oid) return false

        return true
    }

    override fun hashCode(): Int {
        var result = value.hashCode()
        result = 31 * result + oid.hashCode()
        return result
    }

    companion object : Asn1Decodable<Asn1Sequence, AttributeTypeAndValue> {

        @Throws(Asn1Exception::class)
        override fun decodeFromTlv(src: Asn1Sequence): AttributeTypeAndValue = runRethrowing {
            val oid = (src.nextChild() as Asn1Primitive).readOid()
            if (oid.nodes.size >= 3 && oid.toString().startsWith("2.5.4.")) {
                val asn1String = src.nextChild() as Asn1Primitive
                val str = runCatching { (asn1String).readString() }
                if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous elements in RDN")
                return when (oid) {
                    CommonName.OID -> str.fold(onSuccess = { CommonName(it) }, onFailure = { CommonName(asn1String) })
                    Country.OID -> str.fold(onSuccess = { Country(it) }, onFailure = { Country(asn1String) })
                    Organization.OID -> str.fold(
                        onSuccess = { Organization(it) },
                        onFailure = { Organization(asn1String) })

                    OrganizationalUnit.OID -> str.fold(
                        onSuccess = { OrganizationalUnit(it) },
                        onFailure = { OrganizationalUnit(asn1String) })

                    else -> Other(oid, asn1String)
                }
            }
            return Other(oid, src.nextChild())
                .also { if (src.hasMoreChildren()) throw Asn1StructuralException("Superfluous elements in RDN") }
        }
    }
}