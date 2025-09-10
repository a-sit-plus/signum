package io.kotest.provided.at.asitplus.signum.indispensable.asn1

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/* ---------- asn1strings.json ---------- */
@Serializable
data class Asn1StringFixture(
    @SerialName("string_tests") val stringTests: Asn1StringCases = Asn1StringCases()
)

@Serializable
data class Asn1StringCases(
    @SerialName("numeric") val numeric: Asn1StringCase = Asn1StringCase(),
    @SerialName("printable") val printable: Asn1StringCase = Asn1StringCase(),
    @SerialName("visible") val visible: Asn1StringCase = Asn1StringCase(),
    @SerialName("ia5") val ia5: Asn1StringCase = Asn1StringCase(),
    @SerialName("utf8") val utf8: Asn1StringCase = Asn1StringCase(),
    @SerialName("teletex") val teletex: Asn1StringCase = Asn1StringCase(),
    @SerialName("graphic") val graphic: Asn1StringCase = Asn1StringCase(),
    @SerialName("bmp") val bmp: Asn1StringCase = Asn1StringCase(),
    @SerialName("videotex") val videotex: Asn1StringCase = Asn1StringCase(),
    @SerialName("universal") val universal: Asn1StringCase = Asn1StringCase()
)

@Serializable
data class Asn1StringCase(
    val valid: List<String> = emptyList(),
    val invalid: List<String> = emptyList()
)