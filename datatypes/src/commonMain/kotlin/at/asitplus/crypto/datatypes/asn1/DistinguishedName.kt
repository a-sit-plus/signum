package at.asitplus.crypto.datatypes.asn1

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
sealed class DistinguishedName : Asn1Encodable<Asn1Set> {
    abstract val oid: ObjectIdentifier
    abstract val value: Asn1Element

    @Serializable
    @SerialName("CN")
    class CommonName(override val value: Asn1Element) : DistinguishedName() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.commonName
        }
    }

    @Serializable
    @SerialName("C")
    class Country(override val value: Asn1Element) : DistinguishedName() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.countryName
        }
    }

    @Serializable
    @SerialName("O")
    class Organization(override val value: Asn1Element) : DistinguishedName() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationName
        }
    }

    @Serializable
    @SerialName("OU")
    class OrganizationalUnit(override val value: Asn1Element) : DistinguishedName() {
        override val oid = OID

        constructor(str: Asn1String) : this(Asn1Primitive(str.tag, str.value.encodeToByteArray()))

        companion object {
            val OID = KnownOIDs.organizationalUnitName
        }
    }

    @Serializable
    @SerialName("?")
    class Other(override val oid: ObjectIdentifier, override val value: Asn1Element) : DistinguishedName() {
        constructor(oid: ObjectIdentifier, str: Asn1String) : this(
            oid,
            Asn1Primitive(str.tag, str.value.encodeToByteArray())
        )
    }

    override fun encodeToTlv() = asn1Set {
        sequence {
            oid { oid }
            append { value }
        }
    }

    companion object : Asn1Decodable<Asn1Set, DistinguishedName> {

        override fun decodeFromTlv(src: Asn1Set): DistinguishedName {
            if (src.children.size != 1) throw IllegalArgumentException("Invalid Subject Structure")
            val sequence = src.nextChild() as Asn1Sequence
            val oid = (sequence.nextChild() as Asn1Primitive).readOid()
            if (oid.nodes.size >= 3 && oid.toString().startsWith("2.5.4.")) {
                val asn1String = sequence.nextChild() as Asn1Primitive
                val str = runCatching { (asn1String).readString() }
                if (sequence.hasMoreChildren()) throw IllegalArgumentException("Superfluous elements in RDN")
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
            return Other(oid, sequence.nextChild())
                .also { if (sequence.hasMoreChildren()) throw IllegalArgumentException("Superfluous elements in RDN") }
        }
    }
}

