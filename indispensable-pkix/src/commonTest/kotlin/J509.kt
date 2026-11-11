package at.asitplus.signum.indispensable.pki

import at.asitplus.signum.indispensable.*
import at.asitplus.nonFatalOrThrow
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.indispensable.SignumEncodingHelpers.decodeFrom
import at.asitplus.signum.indispensable.SignumEncodingHelpers.encodeTo
import at.asitplus.signum.indispensable.pki.attributes.CommonName
import at.asitplus.signum.indispensable.pki.extn.*
import at.asitplus.signum.indispensable.pki.x500.*
import at.asitplus.signum.indispensable.sign.*
import at.asitplus.awesn1.ObjectIdentifier
import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.serialization.json.*
import kotlin.time.Instant

/** Test-only JSON representation. No DER blobs or ASN.1 conversions are used by these codecs.
 * ponytail: only ECDSA/SHA-256 certificate contents are supported; extend the profile when a test needs another algorithm.
 */
internal object J509 {
    private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(mapOf(*fields))
    private fun text(value: Any) = JsonPrimitive(value.toString())
    private fun bool(value: Boolean) = JsonPrimitive(value)
    private fun bytes(value: ByteArray) = JsonPrimitive(value.toHexString())
    private fun JsonObject.s(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.flag(key: String) = getValue(key).jsonPrimitive.boolean
    private fun JsonObject.list(key: String) = getValue(key).jsonArray
    private fun JsonObject.oid() = ObjectIdentifier(s("oid"))
    private fun JsonObject.optional(key: String) = get(key)?.takeUnless { it is JsonNull }
    private fun JsonObject.number(key: String) = optional(key)?.jsonPrimitive?.content?.let { BigInteger.parseString(it) }
    private inline fun <reified T : WithSourceRepresentation> read(node: JsonObject, crossinline fn: (JsonObject) -> T): T = decodeFrom(fn)(node)
    private inline fun <reified T : WithSourceRepresentation> write(value: T, crossinline fn: (T) -> JsonObject): JsonObject = value.encodeTo(fn)

    fun encode(value: TbsCertificate): String = certificate(value).toString()
    fun decode(value: String): TbsCertificate = certificate(Json.parseToJsonElement(value).jsonObject)

    fun attribute(value: AttributeTypeAndValue): JsonObject = write(value) {
        require(it is TextAttributeTypeAndValue) { "No J509 conversion for attribute ${it.oid}" }
        obj("oid" to text(it.oid), "text" to text(it.text))
    }
    fun attribute(node: JsonObject): AttributeTypeAndValue = read(node) {
        val oid = it.oid()
        val descriptor = at.asitplus.signum.Signum.attributeDescriptorFor(oid)
        try {
            val value = it.optional("text")?.jsonPrimitive?.content
            if (value == null && descriptor == null) AttributeTypeAndValue(oid)
            else {
                require(value != null) { "Invalid J509 attribute $oid" }
                descriptor?.fromString(value) ?: TextAttributeTypeAndValue(oid, value)
            }
        } catch (failure: Throwable) {
            AttributeTypeAndValue(oid, UnsupportedCryptoException("Cannot decode J509 attribute $oid", failure.nonFatalOrThrow()))
        }
    }
    private fun name(value: Name) = JsonArray(value.relativeDistinguishedNames.map { rdn -> JsonArray(rdn.attrsAndValues.map(::attribute)) })
    private fun name(node: JsonElement) = Name(node.jsonArray.map { rdn -> RelativeDistinguishedName(rdn.jsonArray.map { attribute(it.jsonObject) }.toSet()) })

    fun other(value: OtherName): JsonObject = write(value) {
        val payload = when (it) {
            is HardwareModuleName -> obj("hardwareType" to text(it.hardwareType), "serial" to bytes(it.serial))
            is SmtpUtf8Mailbox -> obj("address" to text(it.address))
            is MacAddressName -> obj("address" to bytes(it.address))
            else -> error("No J509 conversion for otherName ${it.oid}")
        }
        obj("oid" to text(it.oid), "value" to payload)
    }
    fun other(node: JsonObject): OtherName = read(node) {
        val oid = it.oid()
        val value = it.getValue("value").jsonObject
        when (oid) {
            HardwareModuleName.OID -> HardwareModuleName(ObjectIdentifier(value.s("hardwareType")), value.s("serial").hexToByteArray())
            SmtpUtf8Mailbox.OID -> SmtpUtf8Mailbox(value.s("address"))
            MacAddressName.OID -> MacAddressName(value.s("address").hexToByteArray())
            else -> OtherName(oid)
        }
    }
    private fun generalName(value: GeneralName): JsonObject {
        if (value is OtherName) return obj("kind" to text("other"), "value" to other(value))
        return write(value) {
            when (it) {
                is DNSName -> obj("kind" to text("dns"), "value" to text(it.value))
                is RFC822Name -> obj("kind" to text("email"), "value" to text(it.value))
                is UriName -> obj("kind" to text("uri"), "value" to text(it.host))
                is IPAddressName -> obj("kind" to text("ip"), "value" to text(it.toString()))
                is RegisteredIDName -> obj("kind" to text("oid"), "value" to text(it.value))
                is DirectoryName -> obj("kind" to text("directory"), "value" to name(it.name))
                is EDIPartyName -> obj("kind" to text("edi"), "partyName" to text(it.partyName),
                    "nameAssigner" to (it.nameAssigner?.let(::text) ?: JsonNull))
                else -> error("Unsupported J509 name")
            }
        }
    }
    private fun generalName(node: JsonObject): GeneralName {
        if (node.s("kind") == "other") return other(node.getValue("value").jsonObject)
        return read(node) {
            when (it.s("kind")) {
                "dns" -> DNSName(it.s("value"))
                "email" -> RFC822Name(it.s("value"))
                "uri" -> UriName(it.s("value"))
                "ip" -> IPAddressName.fromString(it.s("value"))
                "oid" -> RegisteredIDName(ObjectIdentifier(it.s("value")))
                "directory" -> DirectoryName(name(it.getValue("value")))
                "edi" -> EDIPartyName(it.s("partyName"), it["nameAssigner"]?.jsonPrimitive?.contentOrNull)
                else -> error("Unsupported J509 name")
            }
        }
    }
    fun qualifier(value: PolicyQualifierInfo): JsonObject = write(value) {
        val payload = when (it) {
            is CpsUri -> obj("uri" to text(it.uri))
            is UserNotice -> obj("text" to (it.explicitText?.let(::text) ?: JsonNull), "notice" to (it.noticeRef?.let { n ->
                obj("organization" to text(n.organization), "numbers" to JsonArray(n.noticeNumbers.map(::text)))
            } ?: JsonNull))
            else -> error("No J509 conversion for qualifier ${it.oid}")
        }
        obj("oid" to text(it.oid), "value" to payload)
    }
    fun qualifier(node: JsonObject): PolicyQualifierInfo = read(node) {
        val oid = it.oid()
        val payload = it.getValue("value").jsonObject
        when (oid) {
            CpsUri("").oid -> CpsUri(payload.s("uri"))
            UserNotice().oid -> UserNotice(payload.optional("notice")?.jsonObject?.let { n ->
                NoticeReference(n.s("organization"), n.list("numbers").map { number -> BigInteger.parseString(number.jsonPrimitive.content) })
            }, payload.optional("text")?.jsonPrimitive?.content)
            else -> PolicyQualifierInfo(oid)
        }
    }
    private fun subtree(value: GeneralSubtree) = obj("base" to generalName(value.base), "min" to text(value.minimum), "max" to (value.maximum?.let(::text) ?: JsonNull))
    private fun subtree(node: JsonObject) = GeneralSubtree(generalName(node.getValue("base").jsonObject), node.number("min")!!, node.number("max"))
    private fun trees(value: GeneralSubtrees?): JsonElement = value?.let { JsonArray(it.trees.map(::subtree)) } ?: JsonNull
    private fun trees(value: JsonElement?): GeneralSubtrees? = value?.takeUnless { it is JsonNull }?.let { GeneralSubtrees(it.jsonArray.map { n -> subtree(n.jsonObject) }) }

    fun extension(value: CertificateExtension): JsonObject = write(value) {
        val payload = when (it) {
            is BasicConstraints -> obj("ca" to bool(it.ca), "path" to (it.pathLenConstraint?.let(::text) ?: JsonNull))
            is KeyUsage -> obj("bits" to JsonArray(it.keyUsage.map { b -> text(b.name) }))
            is SubjectKeyIdentifier -> obj("id" to bytes(it.keyIdentifier))
            is AuthorityKeyIdentifier -> obj("id" to (it.keyIdentifier?.let(::bytes) ?: JsonNull), "issuer" to JsonArray(it.authorityCertIssuer.map(::generalName)), "serial" to (it.authorityCertSerialNumber?.let(::text) ?: JsonNull))
            is ExtendedKeyUsage -> obj("oids" to JsonArray(it.keyUsages.map(::text)))
            is InhibitAnyPolicy -> obj("skip" to text(it.skipCerts))
            is PolicyConstraints -> obj("explicit" to (it.requireExplicitPolicy?.let(::text) ?: JsonNull), "mapping" to (it.inhibitPolicyMapping?.let(::text) ?: JsonNull))
            is PolicyMappings -> obj("mappings" to JsonArray(it.policyMappings.map { m -> obj("issuer" to text(m.issuerDomain), "subject" to text(m.subjectDomain)) }))
            is CertificatePolicies -> obj("policies" to JsonArray(it.certificatePolicies.map { p -> obj("oid" to text(p.oid), "qualifiers" to JsonArray(p.policyQualifiers.map(::qualifier))) }))
            is NameConstraints -> obj("permitted" to trees(it.permitted), "excluded" to trees(it.excluded))
            is AlternativeNamesExtension -> obj("names" to JsonArray(it.generalNames.map(::generalName)))
            else -> error("No J509 conversion for extension ${it.oid}")
        }
        obj("oid" to text(it.oid), "critical" to bool(it.critical), "value" to payload)
    }
    fun extension(node: JsonObject): CertificateExtension = read(node) {
        val oid = it.oid(); val critical = it.flag("critical"); val p = it.getValue("value").jsonObject
        when (oid) {
            BasicConstraints.oid -> BasicConstraints(p.flag("ca"), p.optional("path")?.jsonPrimitive?.content?.toUInt(), critical)
            KeyUsage.oid -> KeyUsage(p.list("bits").map { b -> UsageBit.valueOf(b.jsonPrimitive.content) }.toSet(), critical)
            SubjectKeyIdentifier.oid -> SubjectKeyIdentifier(p.s("id").hexToByteArray(), critical)
            AuthorityKeyIdentifier.oid -> AuthorityKeyIdentifier(p.optional("id")?.jsonPrimitive?.content?.hexToByteArray(), p.list("issuer").map { n -> generalName(n.jsonObject) }, p.number("serial"), critical)
            ExtendedKeyUsage.oid -> ExtendedKeyUsage(p.list("oids").map { o -> ObjectIdentifier(o.jsonPrimitive.content) }.toSet(), critical)
            InhibitAnyPolicy.oid -> InhibitAnyPolicy(p.s("skip").toInt(), critical)
            PolicyConstraints.oid -> PolicyConstraints(p.optional("explicit")?.jsonPrimitive?.content?.toInt(), p.optional("mapping")?.jsonPrimitive?.content?.toInt(), critical)
            PolicyMappings.oid -> PolicyMappings(p.list("mappings").map { m -> CertificatePolicyMap(ObjectIdentifier(m.jsonObject.s("issuer")), ObjectIdentifier(m.jsonObject.s("subject"))) }, critical)
            CertificatePolicies.oid -> CertificatePolicies(p.list("policies").map { policy -> policy.jsonObject.let { q -> PolicyInformation(q.oid(), q.list("qualifiers").map { v -> qualifier(v.jsonObject) }) } }, critical)
            NameConstraints.oid -> NameConstraints(trees(p["permitted"]), trees(p["excluded"]), critical)
            SubjectAlternativeName(emptyList()).oid -> SubjectAlternativeName(p.list("names").map { n -> generalName(n.jsonObject) }, critical)
            IssuerAlternativeName(emptyList()).oid -> IssuerAlternativeName(p.list("names").map { n -> generalName(n.jsonObject) }, critical)
            else -> J509OnlyExtension(oid, critical)
        }
    }
    fun csrAttribute(value: CsrAttribute): JsonObject = write(value) {
        require(it is ExtensionRequest) { "No J509 conversion for CSR attribute ${it.oid}" }
        obj("oid" to text(it.oid), "extensions" to JsonArray(it.extensions.map(::extension)))
    }
    fun csrAttribute(node: JsonObject): CsrAttribute = read(node) {
        if (it.oid() != CsrAttribute.EXTENSION_REQUEST_OID) CsrAttribute(it.oid())
        else try {
            ExtensionRequest(it.list("extensions").map { e -> extension(e.jsonObject) })
        } catch (failure: Throwable) {
            CsrAttribute(it.oid(), UnsupportedCryptoException("Cannot decode J509 CSR attribute ${it.oid()}", failure.nonFatalOrThrow()))
        }
    }

    private fun certificate(value: TbsCertificate): JsonObject = write(value) {
        require(it.signatureAlgorithm == EcdsaAlgorithm.withSHA256)
        val key = it.publicKey as EcdsaPublicKey
        obj("serial" to text(it.serialNumber), "issuer" to name(it.issuerName), "subject" to name(it.subjectName),
            "from" to text(it.validFrom.epochSeconds), "until" to text(it.validUntil.epochSeconds),
            "curve" to text(key.curve.name), "publicKey" to bytes(key.toAnsiX963Encoded(false)),
            "issuerId" to (it.issuerUniqueID?.let(::bytes) ?: JsonNull), "subjectId" to (it.subjectUniqueID?.let(::bytes) ?: JsonNull),
            "extensions" to JsonArray(it.extensions.map(::extension)))
    }
    private fun certificate(node: JsonObject): TbsCertificate = read(node) {
        TbsCertificate(BigInteger.parseString(it.s("serial")), EcdsaAlgorithm.withSHA256, name(it.getValue("issuer")),
            Instant.fromEpochSeconds(it.s("from").toLong()), Instant.fromEpochSeconds(it.s("until").toLong()), name(it.getValue("subject")),
            EcdsaPublicKey.fromAnsiX963Bytes(ECCurve.valueOf(it.s("curve")), it.s("publicKey").hexToByteArray()),
            it.optional("issuerId")?.jsonPrimitive?.content?.hexToByteArray(), it.optional("subjectId")?.jsonPrimitive?.content?.hexToByteArray(),
            it.list("extensions").map { e -> extension(e.jsonObject) }, strict = false)
    }
}

internal data class J509OnlyExtension(override val oid: ObjectIdentifier, override val critical: Boolean) : CertificateExtension {
    @at.asitplus.signum.SignumInternals override val sourceRepresentation = SourceRepresentationStorage()
}
