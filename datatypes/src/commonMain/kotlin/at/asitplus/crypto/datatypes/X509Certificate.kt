package at.asitplus.crypto.datatypes

import at.asitplus.crypto.datatypes.asn1.*
import at.asitplus.crypto.datatypes.io.ByteArrayBase64Serializer
import kotlinx.datetime.Instant
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Very simple implementation of the meat of an X.509 Certificate:
 * The structure that gets signed
 */
@Serializable
data class TbsCertificate(
    val version: Int = 2,
    val serialNumber: Long,
    val signatureAlgorithm: JwsAlgorithm,
    val issuerName: List<DistingushedName>,
    val validFrom: Instant,
    val validUntil: Instant,
    val subjectName: List<DistingushedName>,
    val publicKey: CryptoPublicKey,
    val extensions: List<X509CertificateExtension>? = null
) {
    fun encodeToDer() = legacySequence {
        version { version }
        long { serialNumber }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        sequence {
            issuerName.forEach {
                set {
                    sequence {
                        distinguishedName { it }
                    }
                }
            }
        }
        sequence {
            utcTime { validFrom }
            utcTime { validUntil }
        }
        sequence {
            subjectName.forEach {
                set {
                    sequence {
                        distinguishedName { it }
                    }
                }
            }
        }
        subjectPublicKey { publicKey }

        extensions?.let {
            if (it.isNotEmpty()) {
                tagged(0xA3) {
                    legacySequence(root = {
                        it.forEach { ext ->
                            append(ext.encoderToDer())
                        }
                    })
                }
            }
        }
    }

    fun encodeToTlv() = asn1Sequence {
        version { version }
        long { serialNumber }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        sequence {
            issuerName.forEach {
                set {
                    sequence {
                        distinguishedName { it }
                    }
                }
            }
        }
        sequence {
            utcTime { validFrom }
            utcTime { validUntil }
        }
        sequence {
            subjectName.forEach {
                set {
                    sequence {
                        distinguishedName { it }
                    }
                }
            }
        }
        subjectPublicKey { publicKey }

        extensions?.let {
            if (it.isNotEmpty()) {
                append {
                    Asn1Primitive(
                        0xA3,
                        asn1Sequence {
                            it.forEach { ext ->
                                append { ext.encodeToTlv() }
                            }
                        }.derEncoded
                    )
                }
            }
        }
    }

    companion object {
        @Throws(IllegalArgumentException::class)
        fun decodeFromDer(input: ByteArray): TbsCertificate {
            return runCatching {
                val reader = Asn1Reader(input)
                val version = reader.read(0xA0) { Asn1Reader(it).readInt() }
                val serialNumber = reader.readLong()
                val sigAlg = reader.readSequence(JwsAlgorithm.Companion::decodeFromDer)
                val issuerName = reader.readSequence {
                    var rest = it
                    val names = mutableListOf<DistingushedName>()
                    while (rest.isNotEmpty()) {
                        val nameReader = Asn1Reader(rest)
                        val inner = nameReader.readSet { Asn1Reader(it) }
                        names += inner.readSequence(::decodeRdn)
                        rest = nameReader.rest
                    }
                    names
                }
                val timestamps = reader.readSequence(::decodeTimestamps)
                val subject = reader.readSequence {
                    var rest = it
                    val names = mutableListOf<DistingushedName>()
                    while (rest.isNotEmpty()) {
                        val nameReader = Asn1Reader(rest)
                        val inner = nameReader.readSet { Asn1Reader(it) }
                        names += inner.readSequence(::decodeRdn)
                        rest = nameReader.rest
                    }
                    names
                }
                val cryptoPublicKey = CryptoPublicKey.decodeFromDer(reader)

                val extensions = if (reader.hasMore()) {
                    val extReader = reader.read(0xA3) { Asn1Reader(it) }
                    extReader.readSequence {
                        var rest = it
                        val extns = mutableListOf<X509CertificateExtension>()
                        while (rest.isNotEmpty()) {
                            val nameReader = Asn1Reader(rest)

                            extns += X509CertificateExtension.decodeFromDer(nameReader)
                            rest = nameReader.rest
                        }
                        extns
                    }
                } else null

                return TbsCertificate(
                    version = version,
                    serialNumber = serialNumber,
                    signatureAlgorithm = sigAlg,
                    issuerName = issuerName,
                    validFrom = timestamps.first,
                    validUntil = timestamps.second,
                    subjectName = subject,
                    publicKey = cryptoPublicKey,
                    extensions = extensions,
                )
            }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
        }

        fun decodeFromTlv(input: Asn1Sequence): TbsCertificate {
            return runCatching {
                //TODO make sure to always check for superfluous data
                val version = input.nextChild().let {
                    (it as Asn1Primitive).parse(0xA0) {
                        (Asn1StructureReader(it).readAll().first() as Asn1Primitive).readInt()
                    }
                }
                val serialNumber = (input.nextChild() as Asn1Primitive).readLong()
                val sigAlg = (input.nextChild() as Asn1Sequence).let {
                    if (it.children.size != 1) throw IllegalArgumentException("More than one element for SigAlg!")
                    JwsAlgorithm.decodeFromTlv(it.nextChild() as Asn1Primitive)

                }
                val issuerNames = (input.nextChild() as Asn1Sequence).children.map {
                    it as Asn1Set
                    if (it.children.size != 1) throw IllegalArgumentException("Invalid Issuer Structure")
                    DistingushedName.decodeFromTlv(it.nextChild() as Asn1Sequence)
                }


                val timestamps = decodeTimestamps(input.nextChild() as Asn1Sequence)?:throw IllegalArgumentException("error parsing Timestamps")
                val subject = (input.nextChild() as Asn1Sequence).children.map {
                    it as Asn1Set
                    if (it.children.size != 1) throw IllegalArgumentException("Invalid Subject Structure")
                    DistingushedName.decodeFromTlv(it.nextChild() as Asn1Sequence)
                }

                val cryptoPublicKey = CryptoPublicKey.decodeFromTlv(input.nextChild() as Asn1Sequence)

                val extensions = if (input.hasMoreChildren()) {
                    (input.nextChild() as Asn1Primitive).parse(0xA3){
                        (Asn1StructureReader(it).readAll().first() as Asn1Sequence).children.map {
                            X509CertificateExtension.decodeFromTlv(it as Asn1Sequence)
                        }
                    }
                } else null

                if(input.hasMoreChildren()) throw IllegalArgumentException("Superfluous Data in Certificate Structure")

                return TbsCertificate(
                    version = version,
                    serialNumber = serialNumber,
                    signatureAlgorithm = sigAlg,
                    issuerName = issuerNames,
                    validFrom = timestamps.first,
                    validUntil = timestamps.second,
                    subjectName = subject,
                    publicKey = cryptoPublicKey,
                    extensions = extensions,
                )
            }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
        }

        private fun decodeTimestamps(input: ByteArray): Pair<Instant, Instant>? = runCatching {
            val reader = Asn1Reader(input)
            val firstInstant = reader.readUtcTime()
            val secondInstant = reader.readUtcTime()
            return Pair(firstInstant, secondInstant)
        }.getOrNull()

        private fun decodeTimestamps(input: Asn1Sequence): Pair<Instant, Instant>? = runCatching {

            val firstInstant = (input.nextChild() as Asn1Primitive).readUtcTime()
            val secondInstant = (input.nextChild() as Asn1Primitive).readUtcTime()
            if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous content in Validity")
            return Pair(firstInstant, secondInstant)
        }.getOrNull()

        private fun decodeRdn(input: ByteArray): DistingushedName {
            val reader = Asn1Reader(input)
            val oid = reader.readOid()
            if (oid.startsWith("5504")) {
                val str = reader.readString()
                return when (oid) {
                    DistingushedName.CommonName.OID -> DistingushedName.CommonName(str)
                    DistingushedName.Country.OID -> DistingushedName.Country(str)
                    DistingushedName.Organization.OID -> DistingushedName.Organization(str)
                    DistingushedName.OrganizationalUnit.OID -> DistingushedName.OrganizationalUnit(str)
                    else -> DistingushedName.Other(str, oid)
                }

            }
            throw IllegalArgumentException("Expected RDN, got OID $oid")
        }
    }
}

//TODO auto-sanitize and/or reduce
@Serializable
sealed class Asn1String() {
    abstract val tag: Byte
    abstract val value: String

    @Serializable
    @SerialName("UTF8String")
    class UTF8(override val value: String) : Asn1String() {
        override val tag = BERTags.UTF8_STRING.toByte()
    }

    @Serializable
    @SerialName("PrintableString")
    class Printable(override val value: String) : Asn1String() {
        override val tag = BERTags.PRINTABLE_STRING.toByte()
    }
}

@Serializable
sealed class DistingushedName {
    abstract val oid: String
    abstract val value: Asn1String

    @Serializable
    @SerialName("CN")
    class CommonName(override val value: Asn1String) : DistingushedName() {
        override val oid = OID

        companion object {
            val OID = "550403"
        }
    }

    @Serializable
    @SerialName("C")
    class Country(override val value: Asn1String) : DistingushedName() {
        override val oid = OID

        companion object {
            val OID = "550406"
        }
    }

    @Serializable
    @SerialName("O")
    class Organization(override val value: Asn1String) : DistingushedName() {
        override val oid = OID

        companion object {
            val OID = "55040A"
        }
    }

    @Serializable
    @SerialName("OU")
    class OrganizationalUnit(override val value: Asn1String) : DistingushedName() {
        override val oid = OID

        companion object {
            val OID = "55040B"
        }
    }

    @Serializable
    @SerialName("?")
    class Other(override val value: Asn1String, override val oid: String) : DistingushedName()

    companion object {
        fun decodeFromTlv(input: Asn1Sequence): DistingushedName {
            val oid = (input.nextChild() as Asn1Primitive).readOid()
            if (oid.startsWith("5504")) {
                val str = (input.nextChild() as Asn1Primitive).readString()
                if (input.hasMoreChildren()) throw IllegalArgumentException("Superfluous elements in RDN")
                return when (oid) {
                    DistingushedName.CommonName.OID -> DistingushedName.CommonName(str)
                    DistingushedName.Country.OID -> DistingushedName.Country(str)
                    DistingushedName.Organization.OID -> DistingushedName.Organization(str)
                    DistingushedName.OrganizationalUnit.OID -> DistingushedName.OrganizationalUnit(str)
                    else -> DistingushedName.Other(str, oid)
                }

            }
            throw IllegalArgumentException("Expected RDN, got OID $oid")
        }
    }
}

@Serializable
data class X509CertificateExtension(
    val id: String, val critical: Boolean = false,
    @Serializable(with = ByteArrayBase64Serializer::class) val value: ByteArray
) {

    fun encoderToDer() = legacySequence {
        oid { id }
        if (critical) bool { true }
        octetString { value }
    }

    fun encodeToTlv() = asn1Sequence {
        oid { id }
        if (critical) bool { true }
        octetString { value }
    }

    companion object {

        fun decodeFromDer(src: Asn1Reader): X509CertificateExtension {
            val extReader = src.readSequence { Asn1Reader(it) }
            val id = extReader.readOid()
            val critical =
                if (extReader.rest[0] == BERTags.BOOLEAN.toByte()) extReader.read(BERTags.BOOLEAN) { it[0] == 0xff.toByte() } else false
            val value = extReader.read(BERTags.OCTET_STRING) { it }
            return X509CertificateExtension(id, critical, value)
        }

        fun decodeFromTlv(src: Asn1Sequence): X509CertificateExtension {

            val id = (src.children[0] as Asn1Primitive).readOid()
            val critical =
                if (src.children[1].tag == BERTags.BOOLEAN.toByte()) (src.children[1] as Asn1Primitive).content[0] == 0xff.toByte() else false

            val value = (src.children.last() as Asn1Primitive).parse(BERTags.OCTET_STRING) { it }
            return X509CertificateExtension(id, critical, value)
        }

        fun decodeFromDer(input: ByteArray): X509CertificateExtension = decodeFromDer(Asn1Reader(input))
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as X509CertificateExtension

        if (id != other.id) return false
        if (critical != other.critical) return false
        if (!value.contentEquals(other.value)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = id.hashCode()
        result = 31 * result + critical.hashCode()
        result = 31 * result + value.contentHashCode()
        return result
    }
}

/**
 * Very simple implementation of an X.509 Certificate
 */
@Serializable
data class X509Certificate(
    val tbsCertificate: TbsCertificate,
    val signatureAlgorithm: JwsAlgorithm,
    @Serializable(with = ByteArrayBase64Serializer::class)
    val signature: ByteArray
) {
    fun encodeToDer() = legacySequence {
        tbsCertificate { tbsCertificate }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        bitString { signature }
    }

    fun encodeToTlv() = asn1Sequence {
        tbsCertificate { tbsCertificate }
        sequence {
            sigAlg { signatureAlgorithm }
        }
        bitString { signature }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as X509Certificate

        if (tbsCertificate != other.tbsCertificate) return false
        if (signatureAlgorithm != other.signatureAlgorithm) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = tbsCertificate.hashCode()
        result = 31 * result + signatureAlgorithm.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    companion object {

        fun decodeFromTlv(src:Asn1Sequence): X509Certificate {
            val tbs= TbsCertificate.decodeFromTlv(src.nextChild() as Asn1Sequence)
            val sigAlg = JwsAlgorithm.decodeFromTlv((src.nextChild() as Asn1Sequence).let {
                if (it.children.size!=1) throw IllegalArgumentException("Invalid SigAlg Structure")
                it.nextChild() as Asn1Primitive
            })
            val signature = (src.nextChild() as Asn1Primitive).readBitString()
            if(src.hasMoreChildren()) throw  IllegalArgumentException("Superfluous structure in Certificate Structure")
            return X509Certificate(tbs, sigAlg,signature)
        }

        fun decodeFromDer(input: ByteArray): X509Certificate {
            return runCatching {
                Asn1Reader(input).readSequence(::decodeFromDerInner)
            }.getOrElse { throw if (it is IllegalArgumentException) it else IllegalArgumentException(it) }
        }

        private fun decodeFromDerInner(input: ByteArray): X509Certificate {
            val reader = Asn1Reader(input)
            val tbs = reader.readSequence(TbsCertificate.Companion::decodeFromDer)
            val sigAlg = reader.readSequence(JwsAlgorithm.Companion::decodeFromDer)
            val signature = reader.readBitstring()
            return X509Certificate(
                tbsCertificate = tbs,
                signatureAlgorithm = sigAlg,
                signature = signature
            )
        }

    }
}
