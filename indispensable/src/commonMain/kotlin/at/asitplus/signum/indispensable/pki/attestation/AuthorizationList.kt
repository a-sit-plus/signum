package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.catchingUnwrapped
import at.asitplus.signum.indispensable.asn1.*
import at.asitplus.signum.indispensable.asn1.encoding.*
import at.asitplus.signum.indispensable.misc.BitLength
import kotlinx.datetime.Instant
import kotlinx.datetime.Month
import kotlinx.datetime.number
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Authorization List ASN.1 sequence as [defined by Google](https://source.android.com/docs/security/features/keystore/attestation#schema).
 * This is the meat of the [AttestationKeyDescription] attestation certificate extension.
 * It is also used for secure key import.
 *
 * Every value is nullable because two authorization lists are present in an attestation extension:
 * once for software-enforced values, and once for hardware-enforced value.
 * The actual values are scattered across both instances.
 *
 * **Parsing is lenient:** If a value fails to parse, it is set to zero. In reality,
 * you won't care whether a value is structurally illegal or absent:
 * * If you want to enforce it, it must be present and structurally valid, fulfilling to your constraints
 * * If you don't care for it, you don't care whether it is present, invalid, or absent altogether
 * In case you still want to explore the raw value, check the raw ASN.1 Sequence from the certificate extension and fetch
 * the raw value according to the explicit tag denoting said value.
 */
class AuthorizationList(
    val purpose: Set<KeyPurpose>? = null,
    val algorithm: Algorithm? = null,
    val keySize: KeySize? = null,
    val digest: Set<Digest>? = null,
    val padding: Set<Padding>? = null,
    val ecCurve: ECCurve? = null,
    val rsaPublicExponent: RsaPublicExponent? = null,
    val mgfDigest: MgfDigest? = null,
    val rollbackResistance: RollbackResistance? = null,
    val earlyBootOnly: EarlyBootOnly? = null,
    val activeDateTime: ActiveDateTime? = null,
    val originationExpireDateTime: OriginationExpireDateTime? = null,
    val usageExpireDateTime: UsageExpireDateTime? = null,
    val usageCountLimit: UsageCountLimit? = null,
    val noAuthRequired: NoAuthRequired? = null,
    val userAuthType: UserAuthType? = null,
    val authTimeout: AuthTimeout? = null,
    val allowWhileOnBody: AllowWhileOnBody? = null,
    val trustedUserPresenceRequired: TrustedUserPresenceRequired? = null,
    val trustedConfirmationRequired: TrustedConfirmationRequired? = null,
    val unlockedDeviceRequired: UnlockedDeviceRequired? = null,
    val creationDateTime: CreationDateTime? = null,
    val origin: Origin? = null,
    val rollbackResistent: RollbackResistent? = null,
    val rootOfTrust: RootOfTrust? = null,
    val osVersion: OsVersion? = null,
    val osPatchLevel: OsPatchLevel? = null,
    val attestationApplicationInfo: Set<AttestationApplicationInfo>? = null,
    val attestationApplicationDigest: Set<ByteArray>? = null,
    val attestationIdBrand: AttestationId.Brand? = null,
    val attestationIdDevice: AttestationId.Device? = null,
    val attestationIdProduct: AttestationId.Product? = null,
    val attestationIdSerial: AttestationId.Serial? = null,
    val attestationIdImei: AttestationId.Imei? = null,
    val attestationIdMeid: AttestationId.Meid? = null,
    val attestationIdManufacturer: AttestationId.Manufacturer? = null,
    val attestationIdModel: AttestationId.Model? = null,
    val vendorPatchLevel: PatchLevel.Vendor? = null,
    val bootPatchLevel: PatchLevel.Boot? = null,
    val deviceUniqueAttestation: DeviceUniqueAttestation? = null,
    val attestationIdSecondImei: AttestationId.SecondImei? = null,
    val moduleHash: ModuleHash? = null,
) : Asn1Encodable<Asn1Sequence> {

    init {
        purpose?.let { require(it.isNotEmpty()) }
        digest?.let { require(it.isNotEmpty()) }
        padding?.let { require(it.isNotEmpty()) }
    }

    override fun encodeToTlv() = Asn1.Sequence {
        add(purpose)
        add(algorithm)
        add(keySize)
        add(digest)
        add(padding)
        add(ecCurve)
        add(rsaPublicExponent)
        add(mgfDigest)
        add(rollbackResistance)
        add(earlyBootOnly)
        add(activeDateTime)
        add(originationExpireDateTime)
        add(usageExpireDateTime)
        add(usageCountLimit)
        add(noAuthRequired)
        add(userAuthType)
        add(authTimeout)
        add(allowWhileOnBody)
        add(trustedUserPresenceRequired)
        add(trustedConfirmationRequired)
        add(unlockedDeviceRequired)
        add(creationDateTime)
        add(origin)
        add(rollbackResistent)
        add(rootOfTrust)
        add(osVersion)
        add(osPatchLevel)
        if (attestationApplicationInfo != null || attestationApplicationDigest != null)
            +Asn1.ExplicitlyTagged(AttestationApplicationInfo.explicitTag) {
                +Asn1.OctetStringEncapsulating {
                    +Asn1.Sequence {
                        attestationApplicationInfo?.let { infos -> +Asn1.SetOf { infos.forEach { +it } } }
                        attestationApplicationDigest?.let {
                            +Asn1.SetOf {
                                it.forEach { +Asn1.OctetString(it) }
                            }
                        }
                    }
                }
            }
        add(attestationIdBrand)
        add(attestationIdDevice)
        add(attestationIdProduct)
        add(attestationIdSerial)
        add(attestationIdImei)
        add(attestationIdMeid)
        add(attestationIdManufacturer)
        add(attestationIdModel)
        add(vendorPatchLevel)
        add(bootPatchLevel)
        add(deviceUniqueAttestation)
        add(attestationIdSecondImei)
        add(moduleHash)
    }

    companion object : Asn1Decodable<Asn1Sequence, AuthorizationList> {
        override fun doDecode(src: Asn1Sequence): AuthorizationList {
            val purpose: Set<KeyPurpose>? = KeyPurpose.decodeSet(src)

            val algorithm: Algorithm? = Algorithm.decode(src)
            val keySize: KeySize? = KeySize.decode(src)
            val digest: Set<Digest>? = Digest.decodeSet(src)
            val padding: Set<Padding>? = Padding.decodeSet(src)
            val ecCurve: ECCurve? = ECCurve.decode(src)
            val rsaPublicExponent: RsaPublicExponent? = RsaPublicExponent.decode(src)
            val mgfDigest: MgfDigest? = MgfDigest.decode(src)
            val rollbackResistance = RollbackResistance.decodeNull(src)
            val earlyBootOnly = EarlyBootOnly.decodeNull(src)
            val activeDateTime: ActiveDateTime? = ActiveDateTime.decode(src)
            val originationExpireDateTime: OriginationExpireDateTime? =
                OriginationExpireDateTime.decode(src)
            val usageExpireDateTime: UsageExpireDateTime? = UsageExpireDateTime.decode(src)
            val usageCountLimit: UsageCountLimit? = UsageCountLimit.decode(src)
            val noAuthRequired = NoAuthRequired.decodeNull(src)
            val userAuthType: UserAuthType? = UserAuthType.decode(src)
            val authTimeout: AuthTimeout? = AuthTimeout.decode(src)
            val allowWhileOnBody = AllowWhileOnBody.decodeNull(src)
            val trustedUserPresenceRequired = TrustedUserPresenceRequired.decodeNull(src)
            val trustedConfirmationRequired = TrustedConfirmationRequired.decodeNull(src)
            val unlockedDeviceRequired = UnlockedDeviceRequired.decodeNull(src)
            val creationDateTime: CreationDateTime? = CreationDateTime.decode(src)
            val origin: Origin? = Origin.decode(src)
            val rollbackResistent: RollbackResistent? = RollbackResistent.decodeNull(src)
            val rootOfTrust: RootOfTrust? =
                src[RootOfTrust.explicitTag]?.let { catchingUnwrapped { RootOfTrust.decodeFromTlv(it.asSequence()) }.getOrNull() }
            val osVersion: OsVersion? = OsVersion.decode(src)
            val osPatchLevel: OsPatchLevel? = OsPatchLevel.decode(src)
            val appInfos = (src.children.firstOrNull {
                if (it !is Asn1ExplicitlyTagged) false else
                    it.tag == Asn1.ExplicitTag(AttestationApplicationInfo.explicitTag)
            } as Asn1ExplicitlyTagged?)?.nextChildOrNull()?.let {
                if (it is Asn1EncapsulatingOctetString) it.nextChildOrNull()
                    ?.let { it as? Asn1Sequence } else null
            }
            val attestationApplicationInfo: Set<AttestationApplicationInfo>? =
                appInfos?.nextChildOrNull()?.let {
                    if (it is Asn1Set) it.children.mapNotNull {
                        if (it is Asn1Sequence)
                            AttestationApplicationInfo.decodeFromTlvOrNull(it)
                        else null
                    }
                    else null
                }?.toSet()


            val attestationApplicationDigest: Set<ByteArray>? =
                appInfos?.nextChildOrNull()?.let {
                    if (it is Asn1Set)
                        it.children.mapNotNull { if (it is Asn1OctetString) it.content else null }
                            .toSet()
                    else null
                }

            val attestationIdBrand: AttestationId.Brand? = AttestationId.Brand.decode(src)
            val attestationIdDevice: AttestationId.Device? = AttestationId.Device.decode(src)
            val attestationIdProduct: AttestationId.Product? = AttestationId.Product.decode(src)
            val attestationIdSerial: AttestationId.Serial? = AttestationId.Serial.decode(src)
            val attestationIdImei: AttestationId.Imei? = AttestationId.Imei.decode(src)
            val attestationIdMeid: AttestationId.Meid? = AttestationId.Meid.decode(src)
            val attestationIdManufacturer: AttestationId.Manufacturer? =
                AttestationId.Manufacturer.decode(src)
            val attestationIdModel: AttestationId.Model? = AttestationId.Model.decode(src)
            val vendorPatchLevel: PatchLevel.Vendor? = PatchLevel.Vendor.decode(src)
            val bootPatchLevel: PatchLevel.Boot? = PatchLevel.Boot.decode(src)
            val deviceUniqueAttestation = DeviceUniqueAttestation.decodeNull(src)
            val attestationIdSecondImei: AttestationId.SecondImei? =
                AttestationId.SecondImei.decode(src)
            val moduleHash: ModuleHash? = ModuleHash.decode(src)

            return AuthorizationList(
                purpose,
                algorithm,
                keySize,
                digest,
                padding,
                ecCurve,
                rsaPublicExponent,
                mgfDigest,
                rollbackResistance,
                earlyBootOnly,
                activeDateTime,
                originationExpireDateTime,
                usageExpireDateTime,
                usageCountLimit,
                noAuthRequired,
                userAuthType,
                authTimeout,
                allowWhileOnBody,
                trustedUserPresenceRequired,
                trustedConfirmationRequired,
                unlockedDeviceRequired,
                creationDateTime,
                origin,
                rollbackResistent,
                rootOfTrust,
                osVersion,
                osPatchLevel,
                attestationApplicationInfo,
                attestationApplicationDigest,
                attestationIdBrand,
                attestationIdDevice,
                attestationIdProduct,
                attestationIdSerial,
                attestationIdImei,
                attestationIdMeid,
                attestationIdManufacturer,
                attestationIdModel,
                vendorPatchLevel,
                bootPatchLevel,
                deviceUniqueAttestation,
                attestationIdSecondImei,
                moduleHash
            )

        }

        private inline fun <reified T : Tagged, reified D : Asn1Encodable<Asn1Element>> T.decode(src: Asn1Sequence): D? =
            src[explicitTag]?.let {
                @Suppress("UNCHECKED_CAST")
                (this as Asn1Decodable<Asn1Element, D>).decodeFromTlvOrNull(src = it)
            }

        private inline fun <reified T : Tagged, reified D : Asn1Encodable<Asn1Element>> T.decodeSet(
            src: Asn1Sequence
        ): Set<D>? =
            src[explicitTag]?.let {
                @Suppress("UNCHECKED_CAST")
                (it as Asn1Set).children.mapNotNull {
                    (this as Asn1Decodable<Asn1Element, D>).decodeFromTlvOrNull(
                        it.asPrimitive()
                    )
                }
            }?.toSet()?.let { if (it.isEmpty()) null else it }

        private inline fun <reified T : Tagged, reified D : Asn1Encodable<Asn1Element>> T.decodeSequence(
            src: Asn1Sequence
        ): List<D>? =
            src[explicitTag]?.let {
                @Suppress("UNCHECKED_CAST")
                (it as Asn1Sequence).children.mapNotNull {
                    (this as Asn1Decodable<Asn1Element, D>).decodeFromTlvOrNull(
                        it.asPrimitive()
                    )
                }
            }?.toList()?.let { if (it.isEmpty()) null else it }


        private operator fun Asn1Sequence.get(tag: ULong): Asn1Element? {
            val asn1Tag = Asn1.ExplicitTag(tag)
            return ((children.firstOrNull { (it as Asn1ExplicitlyTagged).tag == asn1Tag } as Asn1ExplicitlyTagged?)?.children)?.singleOrNull
        }

        private inline fun <reified T : Tagged> T.decodeNull(src: Asn1Sequence): T? =
            if (src.hasNull(explicitTag)) this
            else null


        private fun Asn1Sequence.hasNull(tag: ULong): Boolean {
            val asn1Tag = Asn1.ExplicitTag(tag)
            return ((children.firstOrNull { (it as Asn1ExplicitlyTagged).tag == asn1Tag } as Asn1ExplicitlyTagged?)?.children)?.let {
                if (it.size != 1) false
                else catchingUnwrapped { it.first().asPrimitive().readNull() }
                    .fold(onSuccess = { true }, onFailure = { false })
            } ?: false
        }

        private val List<Asn1Element>.singleOrNull: Asn1Element? get() = if (size == 1) first() else null

    }


    private fun Asn1TreeBuilder.add(element: Set<Tagged.WithTag<*>>?) {
        element?.let { +it.encode() }
    }

    private fun Asn1TreeBuilder.add(element: Tagged.WithTag<*>?) {
        element?.let { +Asn1.ExplicitlyTagged(it.tagged.explicitTag) { +it.encodeToTlv() } }
    }

    private fun Asn1TreeBuilder.add(element: Tagged?) {
        element?.let { +Asn1.ExplicitlyTagged(it.explicitTag) { +Asn1.Null() } }
    }

    private val Set<Tagged.WithTag<*>>.explicitTag get() = first().tagged.explicitTag
    private fun Set<Tagged.WithTag<*>>.encode() = Asn1.ExplicitlyTagged(explicitTag) {
        +Asn1.SetOf { forEach { +it } }

    }


    @OptIn(ExperimentalStdlibApi::class)
    override fun toString(): String {
        return "AuthorizationList(" +
                "purpose=$purpose, " +
                "algorithm=$algorithm, " +
                "keySize=$keySize, " +
                "digest=$digest, " +
                "padding=$padding, " +
                "ecCurve=$ecCurve, " +
                "rsaPublicExponent=$rsaPublicExponent, " +
                "mgfDigest=$mgfDigest, " +
                "rollbackResistance=${rollbackResistance != null}, " +
                "earlyBootOnly=${earlyBootOnly != null}, " +
                "activeDateTime=$activeDateTime, " +
                "originationExpireDateTime=$originationExpireDateTime, " +
                "usageExpireDateTime=$usageExpireDateTime, " +
                "usageCountLimit=$usageCountLimit, " +
                "noAuthRequired=${noAuthRequired != null}, " +
                "userAuthType=$userAuthType, " +
                "authTimeout=$authTimeout, " +
                "allowWhileOnBody=${allowWhileOnBody != null}, " +
                "trustedUserPresenceRequired=${trustedUserPresenceRequired != null}, " +
                "trustedConfirmationRequired=${trustedConfirmationRequired != null}, " +
                "unlockedDeviceRequired=${unlockedDeviceRequired != null}, " +
                "creationDateTime=$creationDateTime, " +
                "origin=$origin, " +
                "rollbackResistent=$rollbackResistent, " +
                "rootOfTrust=$rootOfTrust, " +
                "osVersion=$osVersion, " +
                "osPatchLevel=$osPatchLevel, " +
                "attestationApplicationInfo=$attestationApplicationInfo, " +
                "attestationApplicationDigest=${attestationApplicationDigest?.map { it.toHexString() }}, " +
                "attestationIdBrand=$attestationIdBrand, " +
                "attestationIdDevice=$attestationIdDevice, " +
                "attestationIdProduct=$attestationIdProduct, " +
                "attestationIdSerial=$attestationIdSerial, " +
                "attestationIdImei=$attestationIdImei, " +
                "attestationIdMeid=$attestationIdMeid, " +
                "attestationIdManufacturer=$attestationIdManufacturer, " +
                "attestationIdModel=$attestationIdModel, " +
                "vendorPatchLevel=$vendorPatchLevel, " +
                "bootPatchLevel=$bootPatchLevel, " +
                "deviceUniqueAttestation=${deviceUniqueAttestation != null}, " +
                "attestationIdSecondImei=$attestationIdSecondImei, " +
                "moduleHash=$moduleHash" +
                ")"
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is AuthorizationList) return false

        if (purpose != other.purpose) return false
        if (algorithm != other.algorithm) return false
        if (keySize != other.keySize) return false
        if (digest != other.digest) return false
        if (padding != other.padding) return false
        if (ecCurve != other.ecCurve) return false
        if (rsaPublicExponent != other.rsaPublicExponent) return false
        if (mgfDigest != other.mgfDigest) return false
        if (rollbackResistance != other.rollbackResistance) return false
        if (earlyBootOnly != other.earlyBootOnly) return false
        if (activeDateTime != other.activeDateTime) return false
        if (originationExpireDateTime != other.originationExpireDateTime) return false
        if (usageExpireDateTime != other.usageExpireDateTime) return false
        if (usageCountLimit != other.usageCountLimit) return false
        if (noAuthRequired != other.noAuthRequired) return false
        if (userAuthType != other.userAuthType) return false
        if (authTimeout != other.authTimeout) return false
        if (allowWhileOnBody != other.allowWhileOnBody) return false
        if (trustedUserPresenceRequired != other.trustedUserPresenceRequired) return false
        if (trustedConfirmationRequired != other.trustedConfirmationRequired) return false
        if (unlockedDeviceRequired != other.unlockedDeviceRequired) return false
        if (creationDateTime != other.creationDateTime) return false
        if (origin != other.origin) return false
        if (rollbackResistent != other.rollbackResistent) return false
        if (rootOfTrust != other.rootOfTrust) return false
        if (osVersion != other.osVersion) return false
        if (osPatchLevel != other.osPatchLevel) return false
        if (attestationApplicationInfo != other.attestationApplicationInfo) return false
        if (attestationApplicationDigest != other.attestationApplicationDigest) return false
        if (attestationIdBrand != other.attestationIdBrand) return false
        if (attestationIdDevice != other.attestationIdDevice) return false
        if (attestationIdProduct != other.attestationIdProduct) return false
        if (attestationIdSerial != other.attestationIdSerial) return false
        if (attestationIdImei != other.attestationIdImei) return false
        if (attestationIdMeid != other.attestationIdMeid) return false
        if (attestationIdManufacturer != other.attestationIdManufacturer) return false
        if (attestationIdModel != other.attestationIdModel) return false
        if (vendorPatchLevel != other.vendorPatchLevel) return false
        if (bootPatchLevel != other.bootPatchLevel) return false
        if (deviceUniqueAttestation != other.deviceUniqueAttestation) return false
        if (attestationIdSecondImei != other.attestationIdSecondImei) return false
        if (moduleHash != other.moduleHash) return false

        return true
    }

    override fun hashCode(): Int {
        var result = purpose?.hashCode() ?: 0
        result = 31 * result + (algorithm?.hashCode() ?: 0)
        result = 31 * result + (keySize?.hashCode() ?: 0)
        result = 31 * result + (digest?.hashCode() ?: 0)
        result = 31 * result + (padding?.hashCode() ?: 0)
        result = 31 * result + (ecCurve?.hashCode() ?: 0)
        result = 31 * result + (rsaPublicExponent?.hashCode() ?: 0)
        result = 31 * result + (mgfDigest?.hashCode() ?: 0)
        result = 31 * result + (rollbackResistance?.hashCode() ?: 0)
        result = 31 * result + (earlyBootOnly?.hashCode() ?: 0)
        result = 31 * result + (activeDateTime?.hashCode() ?: 0)
        result = 31 * result + (originationExpireDateTime?.hashCode() ?: 0)
        result = 31 * result + (usageExpireDateTime?.hashCode() ?: 0)
        result = 31 * result + (usageCountLimit?.hashCode() ?: 0)
        result = 31 * result + (noAuthRequired?.hashCode() ?: 0)
        result = 31 * result + (userAuthType?.hashCode() ?: 0)
        result = 31 * result + (authTimeout?.hashCode() ?: 0)
        result = 31 * result + (allowWhileOnBody?.hashCode() ?: 0)
        result = 31 * result + (trustedUserPresenceRequired?.hashCode() ?: 0)
        result = 31 * result + (trustedConfirmationRequired?.hashCode() ?: 0)
        result = 31 * result + (unlockedDeviceRequired?.hashCode() ?: 0)
        result = 31 * result + (creationDateTime?.hashCode() ?: 0)
        result = 31 * result + (origin?.hashCode() ?: 0)
        result = 31 * result + (rollbackResistent?.hashCode() ?: 0)
        result = 31 * result + (rootOfTrust?.hashCode() ?: 0)
        result = 31 * result + (osVersion?.hashCode() ?: 0)
        result = 31 * result + (osPatchLevel?.hashCode() ?: 0)
        result = 31 * result + (attestationApplicationInfo?.hashCode() ?: 0)
        result = 31 * result + (attestationApplicationDigest?.hashCode() ?: 0)
        result = 31 * result + (attestationIdBrand?.hashCode() ?: 0)
        result = 31 * result + (attestationIdDevice?.hashCode() ?: 0)
        result = 31 * result + (attestationIdProduct?.hashCode() ?: 0)
        result = 31 * result + (attestationIdSerial?.hashCode() ?: 0)
        result = 31 * result + (attestationIdImei?.hashCode() ?: 0)
        result = 31 * result + (attestationIdMeid?.hashCode() ?: 0)
        result = 31 * result + (attestationIdManufacturer?.hashCode() ?: 0)
        result = 31 * result + (attestationIdModel?.hashCode() ?: 0)
        result = 31 * result + (vendorPatchLevel?.hashCode() ?: 0)
        result = 31 * result + (bootPatchLevel?.hashCode() ?: 0)
        result = 31 * result + (deviceUniqueAttestation?.hashCode() ?: 0)
        result = 31 * result + (attestationIdSecondImei?.hashCode() ?: 0)
        result = 31 * result + (moduleHash?.hashCode() ?: 0)
        return result
    }


    interface IntEncodable : Asn1Encodable<Asn1Primitive>, Tagged.WithTag<Asn1Primitive> {
        val intValue: Asn1Integer

        override fun encodeToTlv() = intValue.encodeToTlv()
    }

    sealed class Tagged(val explicitTag: ULong) {
        sealed interface WithTag<A : Asn1Element> : Asn1Encodable<A> {
            val tagged: Tagged
        }
    }


    enum class KeyPurpose(override val intValue: Asn1Integer) : IntEncodable {
        ENCRYPT(Asn1Integer(0)),
        DECRYPT(Asn1Integer(1)),
        SIGN(Asn1Integer(2)),
        VERIFY(Asn1Integer(3)),
        DERIVE_KEY(Asn1Integer(4)),
        WRAP_KEY(Asn1Integer(5));

        companion object Tag : Tagged(1uL), Asn1Decodable<Asn1Primitive, KeyPurpose> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())

        }

        override val tagged get() = Tag

    }

    enum class Algorithm(override val intValue: Asn1Integer) : IntEncodable {
        RSA(Asn1Integer(1)),
        EC(Asn1Integer(3)),
        AES(Asn1Integer(32)),
        HMAC(Asn1Integer(128));

        companion object Tag : Tagged(2uL), Asn1Decodable<Asn1Primitive, Algorithm> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class KeySize private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(keyLength: BitLength) : this(Asn1Integer(keyLength.bits))

        companion object Tag : Tagged(3uL), Asn1Decodable<Asn1Primitive, KeySize> {
            override fun doDecode(src: Asn1Primitive) = KeySize(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "KeySize(intValue=$intValue)"
        }
    }

    enum class Digest(override val intValue: Asn1Integer) : IntEncodable {
        NONE(Asn1Integer(0)),
        MD5(Asn1Integer(1)),
        SHA1(Asn1Integer(2)),
        SHA_2_224(Asn1Integer(3)),
        SHA_2_256(Asn1Integer(4)),
        SHA_2_384(Asn1Integer(5)),
        SHA_2_512(Asn1Integer(6));

        companion object Tag : Tagged(5uL), Asn1Decodable<Asn1Primitive, Digest> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    enum class Padding(override val intValue: Asn1Integer) : IntEncodable {
        NONE(Asn1Integer(1)),
        RSA_OAEP(Asn1Integer(2)),
        RSA_PSS(Asn1Integer(3)),
        RSA_PKCS1_1_5_ENCRYPT(Asn1Integer(4)),
        RSA_PKCS1_1_5_SIGN(Asn1Integer(5)),
        PKCS7(Asn1Integer(64));

        companion object Tag : Tagged(6uL), Asn1Decodable<Asn1Primitive, Padding> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }


    enum class ECCurve(override val intValue: Asn1Integer) : IntEncodable {
        P_224(Asn1Integer(0)),
        P_256(Asn1Integer(1)),
        P_384(Asn1Integer(2)),
        P_521(Asn1Integer(3));

        companion object Tag : Tagged(10uL), Asn1Decodable<Asn1Primitive, ECCurve> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class RsaPublicExponent private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(exponent: Asn1Integer.Positive) : this(intValue = exponent)

        companion object Tag : Tagged(200uL), Asn1Decodable<Asn1Primitive, RsaPublicExponent> {
            override fun doDecode(src: Asn1Primitive) = RsaPublicExponent(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    //MGF digest is undocumented. tough luck my friend!
    class MgfDigest(override val intValue: Asn1Integer) : IntEncodable {
        companion object Tag : Tagged(203uL), Asn1Decodable<Asn1Primitive, MgfDigest> {
            override fun doDecode(src: Asn1Primitive) = MgfDigest(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    object RollbackResistance : Tagged(303uL) {
    }

    object EarlyBootOnly : Tagged(305uL) {
    }

    class ActiveDateTime private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(notBefore: Instant) : this(Asn1Integer(notBefore.toEpochMilliseconds()))

        companion object Tag : Tagged(400uL), Asn1Decodable<Asn1Primitive, ActiveDateTime> {
            override fun doDecode(src: Asn1Primitive) = ActiveDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class OriginationExpireDateTime private constructor(override val intValue: Asn1Integer) :
        IntEncodable {
        constructor(notAfter: Instant) : this(Asn1Integer(notAfter.toEpochMilliseconds()))

        companion object Tag : Tagged(401uL),
            Asn1Decodable<Asn1Primitive, OriginationExpireDateTime> {
            override fun doDecode(src: Asn1Primitive) =
                OriginationExpireDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class UsageExpireDateTime private constructor(override val intValue: Asn1Integer) :
        IntEncodable {
        constructor(notAfter: Instant) : this(Asn1Integer(notAfter.toEpochMilliseconds()))

        companion object Tag : Tagged(402uL), Asn1Decodable<Asn1Primitive, UsageCountLimit> {
            override fun doDecode(src: Asn1Primitive) = UsageCountLimit(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class UsageCountLimit(override val intValue: Asn1Integer) : IntEncodable {
        companion object Tag : Tagged(405uL), Asn1Decodable<Asn1Primitive, UsageCountLimit> {
            override fun doDecode(src: Asn1Primitive) = UsageCountLimit(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    object NoAuthRequired : Tagged(503uL) {
    }

    enum class UserAuthType(override val intValue: Asn1Integer) : IntEncodable {
        NONE(Asn1Integer(0)),
        PASSWORD(Asn1Integer(1)),
        FINGERPRINT(Asn1Integer(2)),
        ANY(Asn1Integer(UInt.MAX_VALUE));

        companion object Tag : Tagged(504uL), Asn1Decodable<Asn1Primitive, UserAuthType> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    class AuthTimeout private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(duration: Duration) : this(Asn1Integer(duration.inWholeSeconds))

        val duration: Duration =
            Long.decodeFromAsn1ContentBytes(intValue.encodeToAsn1ContentBytes()).seconds

        init {
            require(intValue.magnitude.size <= 4)
        }

        companion object Tag : Tagged(505uL), Asn1Decodable<Asn1Primitive, AuthTimeout> {
            override fun doDecode(src: Asn1Primitive) = AuthTimeout(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "AuthTimeout(intValue=$intValue, duration=$duration)"
        }
    }

    object AllowWhileOnBody : Tagged(506uL) {
    }

    object TrustedUserPresenceRequired : Tagged(507uL) {
    }

    object TrustedConfirmationRequired : Tagged(508uL) {
    }

    object UnlockedDeviceRequired : Tagged(509uL) {
    }

    class CreationDateTime private constructor(override val intValue: Asn1Integer) : IntEncodable {
        constructor(timestamp: Instant) : this(Asn1Integer(timestamp.toEpochMilliseconds()))

        val timestamp: Instant =
            Instant.fromEpochMilliseconds(Long.decodeFromAsn1ContentBytes(intValue.encodeToAsn1ContentBytes()))

        companion object Tag : Tagged(701uL), Asn1Decodable<Asn1Primitive, CreationDateTime> {
            override fun doDecode(src: Asn1Primitive) = CreationDateTime(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "CreationDateTime(intValue=$intValue, timestamp=$timestamp)"
        }
    }

    enum class Origin(override val intValue: Asn1Integer) : IntEncodable {
        GENERATED(Asn1Integer(0)),
        DERIVED(Asn1Integer(1)),
        IMPORTED(Asn1Integer(2)),
        UNKNOWN(Asn1Integer(3));

        companion object Tag : Tagged(702uL), Asn1Decodable<Asn1Primitive, Origin> {
            fun valueOf(int: Asn1Integer) = entries.first { it.intValue == int }
            override fun doDecode(src: Asn1Primitive) = valueOf(src.decodeToAsn1Integer())
        }

        override val tagged get() = Tag
    }

    object RollbackResistent : Tagged(703uL) {
    }

    class RootOfTrust(
        val verifiedBootKeyDigest: ByteArray,
        val deviceLocked: Boolean,
        val verifiedBootState: VerifiedBootState,
        val verifiedBootHash: ByteArray
    ) : Asn1Encodable<Asn1Sequence>, Tagged.WithTag<Asn1Sequence> {
        companion object Tag : Tagged(704uL), Asn1Decodable<Asn1Sequence, RootOfTrust> {
            override fun doDecode(src: Asn1Sequence) = RootOfTrust(
                src.nextChild().asPrimitive().content,
                src.nextChild().asPrimitive().decodeToBoolean(),
                VerifiedBootState.decodeFromTlv(src.nextChild().asPrimitive()),
                src.nextChild().asPrimitive().content
            )
        }


        override val tagged get() = Tag

        override fun encodeToTlv() = Asn1.Sequence {
            +Asn1.OctetString(verifiedBootKeyDigest)
            +Asn1.Bool(deviceLocked)
            +verifiedBootState
            +Asn1.OctetString(verifiedBootHash)
        }


        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String {
            return "RootOfTrust(verifiedBootKeyDigest=${verifiedBootKeyDigest.toHexString()}, deviceLocked=$deviceLocked, verifiedBootState=$verifiedBootState, verifiedBootHash=${verifiedBootHash.toHexString()})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RootOfTrust) return false

            if (deviceLocked != other.deviceLocked) return false
            if (!verifiedBootKeyDigest.contentEquals(other.verifiedBootKeyDigest)) return false
            if (verifiedBootState != other.verifiedBootState) return false
            if (!verifiedBootHash.contentEquals(other.verifiedBootHash)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = deviceLocked.hashCode()
            result = 31 * result + verifiedBootKeyDigest.contentHashCode()
            result = 31 * result + verifiedBootState.hashCode()
            result = 31 * result + verifiedBootHash.contentHashCode()
            return result
        }

        enum class VerifiedBootState(val intValue: UInt) : Asn1Encodable<Asn1Primitive> {
            Verified(0u),
            SelfSigned(1u),
            Unverified(2u),
            Failed(3u),
            ;

            override fun encodeToTlv() =
                Asn1Primitive(BERTags.ENUMERATED, intValue.encodeToAsn1ContentBytes())

            companion object : Asn1Decodable<Asn1Primitive, VerifiedBootState> {
                fun valueOf(int: UInt) = entries.first { it.intValue == int }
                override fun doDecode(src: Asn1Primitive) = src.decodeToEnum<VerifiedBootState>()
            }

        }

    }

    class OsVersion(
        val major: UByte,
        val minor: UByte,
        val sub: UByte
    ) : IntEncodable {
        override val intValue =
            Asn1Integer(sub.toUInt() + minor.toUInt() * 100u + major.toUInt() * 10000u)

        companion object Tag : Tagged(705uL), Asn1Decodable<Asn1Primitive, OsVersion> {
            override fun doDecode(src: Asn1Primitive): OsVersion {
                val raw = Long.decodeFromAsn1ContentBytes(
                    src.decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                val sub = raw % 100
                val minor = (raw % 10000) / 100
                val major = raw / 10000
                return OsVersion(major.toUByte(), minor.toUByte(), sub.toUByte())
            }
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "OsVersion(major=$major, minor=$minor, sub=$sub, intValue=$intValue)"
        }
    }

    class OsPatchLevel(
        val year: UShort,
        val month: Month
    ) : IntEncodable {

        override val intValue = Asn1Integer(month.number.toUInt() + year.toUInt() * 100u)

        companion object Tag : Tagged(706uL), Asn1Decodable<Asn1Primitive, OsPatchLevel> {
            override fun doDecode(src: Asn1Primitive): OsPatchLevel {
                val raw = Long.decodeFromAsn1ContentBytes(
                    src.decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                val year = raw / 100
                val month = Month((raw % 100).toInt())
                return OsPatchLevel(year.toUShort(), month)
            }
        }

        override val tagged get() = Tag
        override fun toString(): String {
            return "OsPatchLevel(year=$year, month=$month, intValue=$intValue)"
        }
    }


    data class AttestationApplicationInfo(
        val packageName: String,
        val version: UInt,
    ) : Asn1Encodable<Asn1Sequence>,
        Tagged.WithTag<Asn1Sequence> {
        companion object Tag : Tagged(709uL),
            Asn1Decodable<Asn1Sequence, AttestationApplicationInfo> {
            override fun doDecode(src: Asn1Sequence) = AttestationApplicationInfo(
                src.nextChild().asOctetString().content.decodeToString(),
                src.nextChild().asPrimitive().decodeToUInt()
            )

        }

        override val tagged get() = Tag

        override fun encodeToTlv() = Asn1.Sequence {
            +Asn1.OctetString(packageName.encodeToByteArray())
            +Asn1.Int(version)
        }

        override fun toString(): String {
            return "AttestationApplicationInfo(packageName='$packageName', version=$version)"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AttestationApplicationInfo) return false

            if (packageName != other.packageName) return false
            if (version != other.version) return false

            return true
        }

        override fun hashCode(): Int {
            var result = packageName.hashCode()
            result = 31 * result + version.hashCode()
            return result
        }
    }

    sealed class AttestationId(val stringValue: String) : Asn1Encodable<Asn1Primitive>,
        Tagged.WithTag<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.OctetString(stringValue.encodeToByteArray())
        override fun toString(): String {
            return "AttestationId(stringValue='$stringValue')"
        }

        class Brand(packageName: String) : AttestationId(packageName) {
            companion object Tag : Tagged(710uL)

            override val tagged get() = Tag
        }

        class Device(packageName: String) : AttestationId(packageName) {
            companion object Tag : Tagged(711uL), Asn1Decodable<Asn1Primitive, Device> {
                override fun doDecode(src: Asn1Primitive) =
                    Device(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Product(name: String) : AttestationId(name) {
            companion object Tag : Tagged(712uL), Asn1Decodable<Asn1Primitive, Product> {
                override fun doDecode(src: Asn1Primitive) =
                    Product(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Serial(number: String) : AttestationId(number) {
            companion object Tag : Tagged(713uL), Asn1Decodable<Asn1Primitive, Serial> {
                override fun doDecode(src: Asn1Primitive) =
                    Serial(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Imei(number: String) : AttestationId(number) {
            companion object Tag : Tagged(714uL), Asn1Decodable<Asn1Primitive, Imei> {
                override fun doDecode(src: Asn1Primitive) =
                    Imei(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Meid(number: String) : AttestationId(number) {
            companion object Tag : Tagged(715uL), Asn1Decodable<Asn1Primitive, Meid> {
                override fun doDecode(src: Asn1Primitive) =
                    Meid(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Manufacturer(name: String) : AttestationId(name) {
            companion object Tag : Tagged(716uL), Asn1Decodable<Asn1Primitive, Manufacturer> {
                override fun doDecode(src: Asn1Primitive) =
                    Manufacturer(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class Model(name: String) : AttestationId(name) {
            companion object Tag : Tagged(717uL), Asn1Decodable<Asn1Primitive, Model> {
                override fun doDecode(src: Asn1Primitive) =
                    Model(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }

        class SecondImei(number: String) : AttestationId(number) {
            companion object Tag : Tagged(723uL), Asn1Decodable<Asn1Primitive, SecondImei> {
                override fun doDecode(src: Asn1Primitive) =
                    SecondImei(src.asOctetString().content.decodeToString())
            }

            override val tagged get() = Tag
        }


    }

    sealed class PatchLevel(
        val year: UShort,
        val month: Month,
        val day: UShort
    ) : IntEncodable {
        override val intValue =
            Asn1Integer(day.toUInt() + month.number.toUInt() * 100u + year.toUInt() * 10000u)

        companion object {
            fun Asn1Primitive.decode(): Triple<UShort, Month, UShort> {
                val raw = Long.decodeFromAsn1ContentBytes(
                    decodeToAsn1Integer().encodeToAsn1ContentBytes()
                )
                val day = raw % 100
                val monthNumber = (raw % 10000) / 100
                val year = raw / 10000
                return Triple(
                    year.toUShort(),
                    Month(monthNumber.toInt()),
                    day.toUShort()
                )
            }
        }

        class Vendor(
            year: UShort,
            month: Month,
            day: UShort
        ) : PatchLevel(year, month, day) {
            companion object Tag : Tagged(718uL), Asn1Decodable<Asn1Primitive, Vendor> {
                override fun doDecode(src: Asn1Primitive): Vendor = src.decode().let { (y, m, d) ->
                    Vendor(y, m, d)
                }

            }

            override val tagged get() = Tag
        }

        class Boot(
            year: UShort,
            month: Month,
            day: UShort
        ) : PatchLevel(year, month, day) {
            companion object Tag : Tagged(719uL), Asn1Decodable<Asn1Primitive, Boot> {
                override fun doDecode(src: Asn1Primitive): Boot = src.decode().let { (y, m, d) ->
                    Boot(y, m, d)
                }
            }

            override val tagged get() = Tag
        }

        override fun toString(): String {
            return "PatchLevel(year=$year, month=$month, day=$day, intValue=$intValue)"
        }
    }

    /**
     * Can only ever be set by privileged system apps
     */
    object DeviceUniqueAttestation : Tagged(720uL) {
    }

    /**
     * #### Undocumented, ChatGPT-generated! Take with a grain of salt!
     * In the context of Android's Keymaster and Keystore systems, the `moduleHash` is a component within the attestation data structure, specifically in the `KeyDescription` sequence. It provides a cryptographic representation of the software environment associated with the key's creation and usage.
     *
     * **Computation of `moduleHash`:**
     *
     * 1. **Modules Collection:**
     *    - The system gathers a set of `Module` entries, each representing an APEX (Android Pony EXpress) module.
     *    - Each `Module` includes:
     *      - **Package Name (`packageName`):** An octet string identifying the module.
     *      - **Version (`version`):** An integer indicating the module's version at boot time.
     *
     * 2. **DER Encoding:**
     *    - The `Modules` set is encoded using Distinguished Encoding Rules (DER), a binary encoding format for data structures described by ASN.1.
     *    - DER encoding ensures a unique, unambiguous representation of the data, which is crucial for consistent hashing.
     *
     * 3. **Ordering:**
     *    - Within the DER encoding process, the `Module` entries are ordered lexicographically by their encoded value.
     *    - This deterministic ordering guarantees that the same set of modules will always produce the same encoded output, ensuring consistency in the hash computation.
     *
     * 4. **SHA-256 Hashing:**
     *    - The system computes the SHA-256 hash of the DER-encoded `Modules` set.
     *    - The resulting 256-bit hash value is the `moduleHash`.
     *
     * This `moduleHash` serves as a fingerprint of the software environment, allowing verification processes to detect any unauthorized changes to the modules. By including the `moduleHash` in the attestation data, the system provides assurance that the key is used within a trusted and unaltered software environment.
     *
     * For a detailed definition of the `Modules` and `Module` structures, as well as the computation of `moduleHash`, you can refer to the Android Open Source Project's documentation on Keymaster's attestation process.
     */
    class ModuleHash(val sha256Digest: ByteArray) : Asn1Encodable<Asn1Primitive>,
        Tagged.WithTag<Asn1Primitive> {
        override fun encodeToTlv() = Asn1.OctetString(sha256Digest)

        @OptIn(ExperimentalStdlibApi::class)
        override fun toString(): String {
            return "ModuleHash(sha256Digest=${sha256Digest.toHexString()})"
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ModuleHash) return false

            if (!sha256Digest.contentEquals(other.sha256Digest)) return false

            return true
        }

        override fun hashCode(): Int {
            return sha256Digest.contentHashCode()
        }


        companion object Tag : Tagged(724uL), Asn1Decodable<Asn1Primitive, ModuleHash> {
            override fun doDecode(src: Asn1Primitive) = ModuleHash(src.asOctetString().content)
        }

        override val tagged get() = Tag
    }

}