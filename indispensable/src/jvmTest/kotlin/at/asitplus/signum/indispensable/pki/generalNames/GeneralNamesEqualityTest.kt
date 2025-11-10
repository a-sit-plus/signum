package at.asitplus.signum.indispensable.pki.generalNames

import at.asitplus.cidre.IpAddress
import at.asitplus.cidre.IpNetwork
import at.asitplus.signum.ExperimentalPkiApi
import at.asitplus.signum.indispensable.asn1.Asn1Element
import at.asitplus.signum.indispensable.asn1.Asn1String
import at.asitplus.signum.indispensable.asn1.encoding.parse
import at.asitplus.signum.indispensable.pki.RelativeDistinguishedName
import at.asitplus.testballoon.invoke
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

val GeneralNamesEqualityTest by testSuite{

    val bytes = byteArrayOf(-96, 30, 6, 3, 42, 3, 4, -96, 23, 12, 21, 115, 111, 109, 101, 32, 111, 116, 104, 101, 114, 32, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114)
    val changedBytes = byteArrayOf(-95, 31, 6, 3, 42, 3, 4, -96, 24, 12, 22, 115, 111, 109, 101, 32, 101, 100, 105, 116, 101, 100, 32, 105, 100, 101, 110, 116, 105, 102, 105, 101, 114)
    val explicitValue1 = Asn1Element.parse(bytes).asExplicitlyTagged()
    val explicitValue2 = Asn1Element.parse(changedBytes).asExplicitlyTagged()

    fun ia5(value: String) = Asn1String.IA5(value)

    "DNSName equals and hashcode" {
        val dns1 = DNSName(ia5("example.com"))
        val dns2 = DNSName(ia5("example.com"))

        dns1 shouldBe dns2
        dns1.hashCode() shouldBe dns2.hashCode()

        val diffValue = DNSName(ia5("sub.example.com"))
        dns1 shouldNotBe  diffValue

        val wildcard1 = DNSName(ia5("*.example.com"), allowWildcard = false, type = GeneralNameOption.NameType.DNS)
        val wildcard2 = DNSName(ia5("*.example.com"), allowWildcard = true, type = GeneralNameOption.NameType.DNS)
        wildcard1 shouldNotBe wildcard2

        val diffType1 = DNSName(ia5("example.com"), allowWildcard = true, type = GeneralNameOption.NameType.URI)
        val diffType2 = DNSName(ia5("example.com"), allowWildcard = true, type = GeneralNameOption.NameType.DNS)
        diffType1 shouldNotBe diffType2

        val modified = dns1.copy(value = ia5("another.com"))
        dns1 shouldNotBe modified
        dns1.hashCode() shouldNotBe modified.hashCode()
    }

    "EDIPartyName equals and hashcode" {
        val edi1 = EDIPartyName(explicitValue1)
        val edi2 = EDIPartyName(explicitValue1)

        edi1 shouldBe edi2
        edi1.hashCode() shouldBe edi2.hashCode()

        val validTrue = EDIPartyName(explicitValue1, isValid = true)
        val validFalse = EDIPartyName(explicitValue1, isValid = false)
        validTrue shouldNotBe validFalse

        val typeOther = EDIPartyName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.OTHER)
        val typeDns = EDIPartyName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.DNS)
        typeOther shouldNotBe typeDns

        val modified = edi1.copy(value = explicitValue2)
        edi1 shouldNotBe modified
        edi1.hashCode() shouldNotBe modified.hashCode()
    }

    "OtherName equals and hashcode" {
        val otherName1 = OtherName(explicitValue1)
        val otherName2 = OtherName(explicitValue1)

        otherName1 shouldBe otherName2
        otherName1.hashCode() shouldBe otherName2.hashCode()

        val validTrue = OtherName(explicitValue1, isValid = true)
        val validFalse = OtherName(explicitValue1, isValid = false)
        validTrue shouldNotBe validFalse

        val typeOther = OtherName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.OTHER)
        val typeDns = OtherName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.DNS)
        typeOther shouldNotBe typeDns

        val modified = otherName1.copy(value = explicitValue2)
        otherName1 shouldNotBe modified
        otherName1.hashCode() shouldNotBe modified.hashCode()
    }

    "X400AddressName equals and hashcode" {
        val x400AddressName1 = X400AddressName(explicitValue1)
        val x400AddressName2 = X400AddressName(explicitValue1)

        x400AddressName1 shouldBe x400AddressName2
        x400AddressName1.hashCode() shouldBe x400AddressName2.hashCode()

        val validTrue = X400AddressName(explicitValue1, isValid = true)
        val validFalse = X400AddressName(explicitValue1, isValid = false)
        validTrue shouldNotBe validFalse

        val typeOther = X400AddressName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.OTHER)
        val typeDns = X400AddressName(explicitValue1, isValid = null, type = GeneralNameOption.NameType.DNS)
        typeOther shouldNotBe typeDns

        val modified = x400AddressName1.copy(value = explicitValue2)
        x400AddressName1 shouldNotBe modified
        x400AddressName1.hashCode() shouldNotBe modified.hashCode()
    }

    "RFC822Name equals and hashcode" {
        val rfcName1 = RFC822Name(ia5("example.com"))
        val rfcName2 = RFC822Name(ia5("example.com"))
        rfcName1 shouldBe rfcName2
        rfcName1.hashCode() shouldBe rfcName2.hashCode()

        val diffValue = RFC822Name(ia5("sub.example.com"))
        rfcName1 shouldNotBe  diffValue

        val diffType1 = RFC822Name(ia5("example.com"), type = GeneralNameOption.NameType.URI)
        val diffType2 = RFC822Name(ia5("example.com"), type = GeneralNameOption.NameType.DNS)
        diffType1 shouldNotBe diffType2

        val modified = rfcName1.copy(value = ia5("another.com"))
        rfcName1 shouldNotBe modified
        rfcName1.hashCode() shouldNotBe modified.hashCode()
    }

    "IPAddressName equals and hashcode" {
        val ip1 = IPAddressName(IpAddress.V4(byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))
        val ip2 = IPAddressName(IpAddress.V4(byteArrayOf(192.toByte(), 168.toByte(), 1, 1)))
        val ip3 = IPAddressName(IpAddress.V4(byteArrayOf(10, 0, 0, 1)))

        ip1 shouldBe ip2
        ip1.hashCode() shouldBe ip2.hashCode()

        ip1 shouldNotBe ip3

        val net1 = IpNetwork("192.168.1.0/24")
        val net2 = IpNetwork("192.168.1.0/24")
        val net3 = IpNetwork("192.168.2.0/24")

        val ipNet1 = IPAddressName(net1)
        val ipNet2 = IPAddressName(net2)
        val ipNet3 = IPAddressName(net3)

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

        val uri1 = UriName("example.com")
        val uri2 = UriName("example.com")
        val uri3 = UriName("sub.example.com")

        uri1 shouldBe uri2
        uri1.hashCode() shouldBe uri2.hashCode()
        uri1 shouldNotBe uri3

        val wildcard1 = UriName(ia5("*.example.com"), allowWildcard = true, performValidation = false)
        val wildcard2 = UriName(ia5("*.example.com"), allowWildcard = false, performValidation = false)
        wildcard1 shouldNotBe wildcard2

        val ipUri1 = UriName("192.168.0.1")
        val ipUri2 = UriName("192.168.0.1")
        val ipUri3 = UriName("10.0.0.1")

        ipUri1 shouldBe ipUri2
        ipUri1.hashCode() shouldBe ipUri2.hashCode()
        ipUri1 shouldNotBe ipUri3

        val ipv6Uri1 = UriName("[2001:db8::1]")
        val ipv6Uri2 = UriName("[2001:db8::1]")
        val ipv6Uri3 = UriName("[2001:db8::2]")

        ipv6Uri1 shouldBe ipv6Uri2
        ipv6Uri1.hashCode() shouldBe ipv6Uri2.hashCode()
        ipv6Uri1 shouldNotBe ipv6Uri3

        val modifiedHost = UriName("modified.com")
        uri1 shouldNotBe modifiedHost
        uri1.hashCode() shouldNotBe modifiedHost.hashCode()

        val wildcardDiff = UriName("*.example.com", allowWildcard = true)
        val wildcardDiff2 = UriName("*.example.org", allowWildcard = true)
        wildcardDiff shouldNotBe wildcardDiff2
    }

    "X500Name equals and hashcode" {

        // Simple single RDN
        val cn1 = RelativeDistinguishedName.fromString("CN=John Doe")
        val cn2 = RelativeDistinguishedName.fromString("CN=John Doe")
        val cn3 = RelativeDistinguishedName.fromString("CN=Jane Doe")

        val x500name1 = X500Name(listOf(cn1))
        val x500name2 = X500Name(listOf(cn2))
        val x500name3 = X500Name(listOf(cn3))

        x500name1 shouldBe x500name2
        x500name1.hashCode() shouldBe x500name2.hashCode()
        x500name1 shouldNotBe x500name3

        // Multiple RDNs
        val rdns1 = listOf(
            RelativeDistinguishedName.fromString("CN=John Doe"),
            RelativeDistinguishedName.fromString("O=Company"),
            RelativeDistinguishedName.fromString("C=US")
        )

        val rdns2 = listOf(
            RelativeDistinguishedName.fromString("CN=John Doe"),
            RelativeDistinguishedName.fromString("O=Company"),
            RelativeDistinguishedName.fromString("C=US")
        )

        val rdns3 = listOf(
            RelativeDistinguishedName.fromString("CN=Jane Doe"),
            RelativeDistinguishedName.fromString("O=Company"),
            RelativeDistinguishedName.fromString("C=US")
        )

        val x500multi1 = X500Name(rdns1)
        val x500multi2 = X500Name(rdns2)
        val x500multi3 = X500Name(rdns3)

        x500multi1 shouldBe x500multi2
        x500multi1.hashCode() shouldBe x500multi2.hashCode()
        x500multi1 shouldNotBe x500multi3
        x500name1 shouldNotBe x500multi1
    }
}