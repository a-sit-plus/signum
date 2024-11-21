package at.asitplus.signum.indispensable

import at.asitplus.signum.ecmath.times
import at.asitplus.signum.indispensable.CryptoPublicKey.EC.Companion.asPublicKey
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*

sealed class CryptoPrivateKey<T: CryptoPublicKey>(val attributes: List<Asn1Element>?) : Asn1Encodable<Asn1Sequence> {

    abstract val publicKey: T?

    class RSA(
        val modulus: Asn1Integer,
        val publicExponent: Asn1Integer,
        val privateExponent: Asn1Integer,
        val prime1: Asn1Integer,
        val prime2: Asn1Integer,
        val exponent1: Asn1Integer,
        val exponent2: Asn1Integer,
        val coefficient: Asn1Integer,
        val otherPrimeInfos: OtherPrimeInfos?,
        attributes: List<Asn1Element>? = null
    ) : CryptoPrivateKey<CryptoPublicKey.RSA>(attributes) {

        override val publicKey = CryptoPublicKey.RSA(modulus, publicExponent)

        class OtherPrimeInfos(
            val prime: Asn1Integer,
            val exponent: Asn1Integer,
            val coefficient: Asn1Integer,
        ) : Asn1Encodable<Asn1Sequence> {
            override fun encodeToTlv() = Asn1.Sequence {
                +prime
                +exponent
                +coefficient
            }

            companion object : Asn1Decodable<Asn1Sequence, OtherPrimeInfos> {
                override fun doDecode(src: Asn1Sequence): OtherPrimeInfos {
                    val prime = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val exponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    val coefficient = src.nextChild().asPrimitive().decodeToAsn1Integer()
                    require(src.hasMoreChildren() == false) { "Superfluous Data in OtherPrimeInfos" }
                    return OtherPrimeInfos(prime, exponent, coefficient)
                }

            }
        }

        fun pkcs1Encode() = Asn1.Sequence {
            if (otherPrimeInfos != null) +Asn1.Int(1)
            else +Asn1.Int(0)
            +modulus
            +publicExponent
            +privateExponent
            +prime1
            +prime2
            +exponent1
            +exponent2
            +coefficient
            otherPrimeInfos?.let { +it }
        }

        companion object : Asn1Decodable<Asn1Sequence, RSA> {

            val oid: ObjectIdentifier = KnownOIDs.rsaEncryption

            override fun doDecode(src: Asn1Sequence): RSA = decodeInternal(src, null)

            //PKCS#1
            fun decodeInternal(src: Asn1Sequence, attributes: List<Asn1Element>?): RSA {
                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 0 || version == 1) { "RSA Private key VERSION must be 0 or 1" }
                val modulus = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val publicExponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val privateExponent = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val prime1 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val prime2 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val exponent1 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val exponent2 = src.nextChild().asPrimitive().decodeToAsn1Integer()
                val coefficient = src.nextChild().asPrimitive().decodeToAsn1Integer()

                val otherPrimeInfos: OtherPrimeInfos? = if (src.hasMoreChildren()) {
                    require(version == 1) { "OtherPrimeInfos is present. RSA private key version must be 1" }
                    OtherPrimeInfos.decodeFromTlv(src.nextChild().asSequence())
                } else {
                    require(version == 0) { "OtherPrimeInfos is present. RSA private key version must be 0" }
                    null
                }
                return RSA(
                    modulus,
                    publicExponent,
                    privateExponent,
                    prime1,
                    prime2,
                    exponent1,
                    exponent2,
                    coefficient,
                    otherPrimeInfos,
                    attributes
                )
            }
        }

        override fun toString() = "RSA private key for public key $publicKey"
    }

    class EC(
        val curve: ECCurve?,
        val privateKeyBytes: Asn1Integer,
        publicKey: CryptoPublicKey.EC?,
        attributes: List<Asn1Element>? = null
    ) :
        CryptoPrivateKey<CryptoPublicKey.EC>(attributes) {

        override val publicKey: CryptoPublicKey.EC? = publicKey ?: curve?.let { crv ->
            privateKeyBytes.toBigInteger().times(crv.generator).asPublicKey(preferCompressed = true)
        }


        override fun toString() = "EC private key${
            publicKey?.let {
                " for public key $it"
            } ?: curve?.let { " for curve $it" } ?: " ${privateKeyBytes.magnitude.size * 8} bit"
        }"

        companion object : Asn1Decodable<Asn1Sequence, EC> {

            val oid: ObjectIdentifier = KnownOIDs.ecPublicKey

            override fun doDecode(src: Asn1Sequence): EC =  decodeInternal(src, attributes = null)

            //SEC1 v2
            fun decodeInternal(
                src: Asn1Sequence,
                predefinedCurve: ECCurve? = null,
                attributes: List<Asn1Element>?
            ): EC {

                fun Asn1ExplicitlyTagged.decodeECParams(): ObjectIdentifier {
                    require(children.size == 1) { "Only a single EC parameter is allowed" }
                    return ObjectIdentifier.decodeFromTlv(nextChild().asPrimitive())
                }

                val version = src.nextChild().asPrimitive().decodeToInt()
                require(version == 1) { "EC public key version must be 1" }
                val privateKeyOctets = src.nextChild().asPrimitiveOctetString().decodeToAsn1Integer(Asn1Element.Tag.OCTET_STRING)
                var params: ObjectIdentifier? = null
                var publicKey: CryptoPublicKey.EC? = null

                //TODO remove duplicated code
                if (src.hasMoreChildren()) {
                    val tagged = src.nextChild().asExplicitlyTagged()
                    when (tagged.tag.tagValue) {
                        0uL -> tagged.decodeECParams().also {
                            require(params == null) { "EC parameters may only occur once" }
                            params = it
                        }

                        1uL -> {
                            require(publicKey == null) { "EC public key may only occur once" }
                            val parsedCurve =
                                params?.let { params -> ECCurve.entries.first { it.oid == params } }
                            predefinedCurve?.let { pre ->
                                parsedCurve?.let { inner ->
                                    require(inner == pre) { "EC Curve OID mismatch" }
                                }
                            }
                            val crv = parsedCurve ?: predefinedCurve
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            publicKey = if (crv != null)
                                CryptoPublicKey.EC.fromAnsiX963Bytes(crv, asAsn1BitString.rawBytes)
                            else CryptoPublicKey.fromIosEncoded(asAsn1BitString.rawBytes) as CryptoPublicKey.EC
                        }
                    }
                }

                if (src.hasMoreChildren()) {
                    val tagged = src.nextChild().asExplicitlyTagged()
                    when (tagged.tag.tagValue) {
                        0uL -> tagged.decodeECParams().also {
                            require(params == null) { "EC parameters may only occur once" }
                            params = it
                        }

                        1uL -> {
                            require(publicKey == null) { "EC public key may only occur once" }
                            val parsedCurve =
                                params?.let { params -> ECCurve.entries.first { it.oid == params } }
                            predefinedCurve?.let { pre ->
                                parsedCurve?.let { inner ->
                                    require(inner == pre) { "EC Curve OID mismatch" }
                                }
                            }
                            val crv = parsedCurve ?: predefinedCurve
                            val asAsn1BitString = tagged.nextChild().asPrimitive().asAsn1BitString()
                            publicKey = if (crv != null)
                                CryptoPublicKey.EC.fromAnsiX963Bytes(crv, asAsn1BitString.rawBytes)
                            else CryptoPublicKey.fromIosEncoded(asAsn1BitString.rawBytes) as CryptoPublicKey.EC
                        }
                    }
                }

                return EC(
                    curve = publicKey?.curve,
                    privateKeyBytes = privateKeyOctets,
                    publicKey = publicKey,
                    attributes
                )
            }
        }


        fun sec1Encode() = Asn1.Sequence {
            +Asn1.Int(1)
            +Asn1PrimitiveOctetString(privateKeyBytes.encodeToAsn1ContentBytes())
            curve?.let { +it.oid }
            publicKey?.let { +Asn1.BitString(it.iosEncoded) }
        }

    }


    override fun encodeToTlv() = Asn1.Sequence {
        +Asn1.Int(0)
        val outer = this
        +Asn1.Sequence {
            when (this@CryptoPrivateKey) {
                is RSA -> {
                    +RSA.oid
                    +Asn1.Null()
                    attributes?.let { attrs ->
                        +Asn1.ExplicitlyTagged(0uL) {
                            attrs.forEach { +it }
                        }
                    }
                    outer.apply { +pkcs1Encode() }
                }

                is EC -> {
                    +EC.oid
                    require(curve != null) { "Cannot PKCS#8-encode an EC key without curve. Re-create it and specify a curve!" }
                    +curve.oid
                    attributes?.let { attrs ->
                        +Asn1.ExplicitlyTagged(0uL) {
                            attrs.forEach { +it }
                        }
                    }
                    outer.apply { +sec1Encode() }
                }
            }
        }
    }

    companion object : Asn1Decodable<Asn1Sequence, CryptoPrivateKey<*>> {
        override fun doDecode(src: Asn1Sequence): CryptoPrivateKey<*> {
            //PKCS8 here
            require(src.nextChild().asPrimitive().decodeToInt() == 0) { "PKCS#8 Private Key VERSION must be 0" }
            val algorithmID = src.nextChild().asSequence()
            val algIdentifier = ObjectIdentifier.decodeFromTlv(algorithmID.nextChild().asPrimitive())
            val algParams = algorithmID.nextChild().asPrimitive()
            require(algorithmID.hasMoreChildren() == false) { "Superfluous Algorithm ID data encountered" }
            val privateKeyStructure = src.nextChild().asEncapsulatingOctetString().let {
                val seq = it.nextChild().asSequence()
                require(it.hasMoreChildren() == false) { "Superfluous private key data encountered" }
                seq
            }
            val attributes: List<Asn1Element>? =
                if (src.hasMoreChildren()) src.nextChild().asExplicitlyTagged().verifyTag(0u)
                else null
            return if (algIdentifier == RSA.oid) {
                algParams.readNull()
                RSA.decodeInternal(privateKeyStructure, attributes)
            } else if (algIdentifier == EC.oid) {
                val predefinedCurve = ECCurve.entries.first { it.oid == ObjectIdentifier.decodeFromTlv(algParams) }
                EC.decodeInternal(privateKeyStructure, predefinedCurve, attributes)
            } else throw IllegalArgumentException("Unknown Algorithm: $algIdentifier")

        }

    }
}