package at.asitplus.signum.indispensable.pki

import at.asitplus.catching
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.Asn1
import at.asitplus.signum.indispensable.asn1.encoding.asAsn1String

/**
 * X.500 Name (used in X.509 Certificates)
 */
data class RelativeDistinguishedName(val attrsAndValues: List<AttributeTypeAndValue>) : Asn1Encodable<Asn1Set> {

    constructor(singleItem: AttributeTypeAndValue) : this(listOf(singleItem))

    override fun encodeToTlv() = runRethrowing {
        Asn1.Set {
            attrsAndValues.forEach { +it }
        }
    }

    companion object : Asn1Decodable<Asn1Set, RelativeDistinguishedName> {
        override fun doDecode(src: Asn1Set): RelativeDistinguishedName = src.decodeRethrowing {
            buildList {
                while (hasNext()) {
                    val child = next().asSequence()
                    add(AttributeTypeAndValue.decodeFromTlv(child))
                }
            }.let(::RelativeDistinguishedName)
        }
    }

    override fun toString() = "DistinguishedName(attrsAndValues=${attrsAndValues.joinToString()})"

}

//TODO: value should be Asn1Primitive???
sealed class AttributeTypeAndValue : Asn1Encodable<Asn1Sequence>, Identifiable {
    abstract val value: Asn1Element

    override fun toString() = value.toString()

    class CommonName(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.commonName
        }
    }

    class Country(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.countryName
        }
    }

    class Organization(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationName
        }
    }

    class OrganizationalUnit(override val value: Asn1Element) : AttributeTypeAndValue() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationalUnitName
        }
    }

    class Other(override val oid: ObjectIdentifier, override val value: Asn1Element) : AttributeTypeAndValue() {
        constructor(oid: ObjectIdentifier, str: Asn1String) : this(
            oid,
            Asn1Primitive(str.tag, str.value.encodeToByteArray())
        )
    }

    override fun encodeToTlv() = Asn1.Sequence {
        +oid
        +value
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
        override fun doDecode(src: Asn1Sequence): AttributeTypeAndValue = src.decodeRethrowing {
            val oid = next().asPrimitive().readOid()
            if (oid.nodes.size >= 3 && oid.toString().startsWith("2.5.4.")) {
                val asn1String = next().asPrimitive()
                val str = catching { (asn1String).asAsn1String() }
                if (hasNext()) throw Asn1StructuralException("Superfluous elements in RDN")
                return@decodeRethrowing when (oid) {
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
            Other(oid, next())
        }

    }
}