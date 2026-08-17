package at.asitplus.signum.indispensable.pki.x500

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpNetwork
import at.asitplus.awesn1.Asn1String
import at.asitplus.awesn1.ObjectIdentifier
import at.asitplus.awesn1.crypto.pki.X509GeneralName
import at.asitplus.awesn1.encoding.Asn1
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.signum.indispensable.pki.X500Name
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

// GeneralName equality is by CHOICE-tagged DER (see AbstractX509GeneralName.equals): two names with the
// same wire encoding are equal, regardless of derived/validation-only fields.
val GeneralNamesEqualityTest by matrixSuite {

    val other1 = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4"), Asn1.Int(1)))
    val other2 = X509GeneralName.Other(X509GeneralName.Other.SemanticValue.Generic(ObjectIdentifier("1.2.3.4"), Asn1.Int(2)))
    val seq1 = Asn1.Sequence { +Asn1.Int(1) }
    val seq2 = Asn1.Sequence { +Asn1.Int(2) }

    fun ia5(value: String) = Asn1String.IA5(value)

    "DNSName equals and hashcode" {
        DNSName(ia5("example.com")) shouldBe DNSName(ia5("example.com"))
        DNSName(ia5("example.com")).hashCode() shouldBe DNSName(ia5("example.com")).hashCode()
        DNSName(ia5("example.com")) shouldNotBe DNSName(ia5("sub.example.com"))
    }

    "EDIPartyName equals and hashcode" {
        EDIPartyName(seq1) shouldBe EDIPartyName(seq1)
        EDIPartyName(seq1).hashCode() shouldBe EDIPartyName(seq1).hashCode()
        EDIPartyName(seq1) shouldNotBe EDIPartyName(seq2)
    }

    "OtherName equals and hashcode" {
        OtherName(other1) shouldBe OtherName(other1)
        OtherName(other1).hashCode() shouldBe OtherName(other1).hashCode()
        OtherName(other1) shouldNotBe OtherName(other2)
    }

    "X400AddressName equals and hashcode" {
        X400AddressName(seq1) shouldBe X400AddressName(seq1)
        X400AddressName(seq1).hashCode() shouldBe X400AddressName(seq1).hashCode()
        X400AddressName(seq1) shouldNotBe X400AddressName(seq2)
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
