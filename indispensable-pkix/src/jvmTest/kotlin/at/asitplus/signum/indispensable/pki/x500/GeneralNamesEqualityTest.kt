package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpNetwork
import at.asitplus.awesn1.Asn1Element
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.encoding.parse
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

// GeneralName equality is by CHOICE-tagged DER (see GeneralName.equals): two names with the same
// wire encoding are equal, regardless of derived/validation-only fields.
val GeneralNamesEqualityTest by matrixSuite {

    val bytes = byteArrayOf(-96, 30, 6, 3, 42, 3, 4, -96, 23, 12, 21, 115, 111, 109, 101, 32, 111, 116, 104, 101, 114, 32, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114)
    val changedBytes = byteArrayOf(-95, 31, 6, 3, 42, 3, 4, -96, 24, 12, 22, 115, 111, 109, 101, 32, 101, 100, 105, 116, 101, 100, 32, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114)
    val explicitValue1 = Asn1Element.parse(bytes).asExplicitlyTagged()
    val explicitValue2 = Asn1Element.parse(changedBytes).asExplicitlyTagged()

    fun ia5(value: String) = Asn1String.IA5(value)

    "DNSName equals and hashcode" {
        DNSName(ia5("example.com")) shouldBe DNSName(ia5("example.com"))
        DNSName(ia5("example.com")).hashCode() shouldBe DNSName(ia5("example.com")).hashCode()
        DNSName(ia5("example.com")) shouldNotBe DNSName(ia5("sub.example.com"))
    }

    "EDIPartyName equals and hashcode" {
        EDIPartyName(explicitValue1) shouldBe EDIPartyName(explicitValue1)
        EDIPartyName(explicitValue1).hashCode() shouldBe EDIPartyName(explicitValue1).hashCode()
        EDIPartyName(explicitValue1) shouldNotBe EDIPartyName(explicitValue2)
    }

    "OtherName equals and hashcode" {
        OtherName(explicitValue1) shouldBe OtherName(explicitValue1)
        OtherName(explicitValue1).hashCode() shouldBe OtherName(explicitValue1).hashCode()
        OtherName(explicitValue1) shouldNotBe OtherName(explicitValue2)
    }

    "X400AddressName equals and hashcode" {
        X400AddressName(explicitValue1) shouldBe X400AddressName(explicitValue1)
        X400AddressName(explicitValue1).hashCode() shouldBe X400AddressName(explicitValue1).hashCode()
        X400AddressName(explicitValue1) shouldNotBe X400AddressName(explicitValue2)
    }

    "RFC822Name equals and hashcode" {
        RFC822Name(ia5("user@example.com")) shouldBe RFC822Name(ia5("user@example.com"))
        RFC822Name(ia5("user@example.com")).hashCode() shouldBe RFC822Name(ia5("user@example.com")).hashCode()
        RFC822Name(ia5("user@example.com")) shouldNotBe RFC822Name(ia5("other@example.com"))
    }

    "IPAddressName equals and hashcode" {
        val ip1 = IPAddressName(IpAddress.V4(byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))
        val ip2 = IPAddressName(IpAddress.V4(byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))
        val ip3 = IPAddressName(IpAddress.V4(byteArrayOf(10, 0, 0, 1)))

        ip1 shouldBe ip2
        ip1.hashCode() shouldBe ip2.hashCode()
        ip1 shouldNotBe ip3

        val ipNet1 = IPAddressName(IpNetwork("192.168.1.0/24"))
        val ipNet2 = IPAddressName(IpNetwork("192.168.1.0/24"))
        val ipNet3 = IPAddressName(IpNetwork("192.168.2.0/24"))

        ipNet1 shouldBe ipNet2
        ipNet1.hashCode() shouldBe ipNet2.hashCode()
        ipNet1 shouldNotBe ipNet3
        ip1 shouldNotBe ipNet1

        val ip6name1 = IPAddressName(IpAddress.V6(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)))
        val ip6name2 = IPAddressName(IpAddress.V6(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)))
        val ip6name3 = IPAddressName(IpAddress.V6(byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)))

        ip6name1 shouldBe ip6name2
        ip6name1.hashCode() shouldBe ip6name2.hashCode()
        ip6name1 shouldNotBe ip6name3
    }

    "UriName equals and hashcode" {
        UriName("example.com") shouldBe UriName("example.com")
        UriName("example.com").hashCode() shouldBe UriName("example.com").hashCode()
        UriName("example.com") shouldNotBe UriName("sub.example.com")

        UriName("192.168.0.1") shouldBe UriName("192.168.0.1")
        UriName("192.168.0.1") shouldNotBe UriName("10.0.0.1")

        UriName("[2001:db8::1]") shouldBe UriName("[2001:db8::1]")
        UriName("[2001:db8::1]") shouldNotBe UriName("[2001:db8::2]")
    }

    "DirectoryName / X500Name equals and hashcode" {
        val cn1 = RelativeDistinguishedName.fromString("2.5.4.3=John Doe")
        val cn3 = RelativeDistinguishedName.fromString("2.5.4.3=Jane Doe")

        X500Name(listOf(cn1)) shouldBe X500Name(listOf(cn1))
        X500Name(listOf(cn1)).hashCode() shouldBe X500Name(listOf(cn1)).hashCode()
        X500Name(listOf(cn1)) shouldNotBe X500Name(listOf(cn3))

        DirectoryName(X500Name(listOf(cn1))) shouldBe DirectoryName(X500Name(listOf(cn1)))
        DirectoryName(X500Name(listOf(cn1))) shouldNotBe DirectoryName(X500Name(listOf(cn3)))
    }
}
