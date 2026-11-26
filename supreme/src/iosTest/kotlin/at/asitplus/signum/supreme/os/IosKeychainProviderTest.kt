@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, at.asitplus.signum.SignumInternals::class)

package at.asitplus.signum.supreme.os

import at.asitplus.signum.dsl.IosSignerConfiguration
import at.asitplus.signum.dsl.IosSigningKeyConfiguration
import at.asitplus.signum.ServiceLoader
import at.asitplus.signum.UnsupportedCryptoException
import at.asitplus.signum.dsl.signer
import at.asitplus.signum.indispensable.PublicKey
import at.asitplus.signum.indispensable.sign.EcdsaAlgorithm
import at.asitplus.signum.indispensable.sign.SignatureAlgorithm
import platform.Security.SecAccessControlRef
import platform.LocalAuthentication.LAContext
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.digest.Digest
import at.asitplus.signum.indispensable.sign.EcdsaPublicKey
import at.asitplus.signum.supreme.azString
import at.asitplus.testballoon.matrix.*
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


private object OpaqueAliasFixtureProvider : IosKeychainOperationsProvider, OpaqueIosKeyBackend {
    override val opaqueKeyBackend: OpaqueIosKeyBackend get() = this
    override val backendId = "org.example.test.opaque"
    var reopenCount = 0

    override fun supports(config: IosSigningKeyConfiguration) = false
    override suspend fun generate(config: IosSigningKeyConfiguration, accessControl: SecAccessControlRef): OpaqueIosKeyMaterial =
        error("fixture generation is not used")
    override suspend fun reopen(
        representationVersion: Int, representation: ByteArray, authenticationContext: LAContext?,
    ): OpenedKey {
        reopenCount++
        error("fixture reopen is not used")
    }
    override fun signatureAlgorithm(publicKey: PublicKey, config: IosSignerConfiguration): SignatureAlgorithm =
        EcdsaAlgorithm(Digest.SHA256, (publicKey as EcdsaPublicKey).curve)
    override fun getOperationsBundle(config: IosSigningKeyConfiguration): IosKeychainOperationsProvider.OperationsBundle? = null
    override fun makeIosSigner(
        alias: String, publicKey: PublicKey, metadata: IosKeyMetadata, config: IosSignerConfiguration,
    ): IosSigner? = null
}

val IosKeychainProviderTest by matrixSuite {
    "Opaque backend IDs are stable namespaced identifiers" - {
        "accepts a reverse-DNS identifier" {
            validateOpaqueBackendId("com.example.crypto.mldsa") shouldBe "com.example.crypto.mldsa"
        }

        "rejects empty, unqualified, and malformed identifiers" {
            listOf("", "x", "abc", "has space", ".starts-with-dot").forEach { id ->
                runCatching { validateOpaqueBackendId(id) }.isFailure shouldBe true
            }
        }
    }

    "Opaque alias record storage" - {
        "round trips private records and deletes them by alias without a backend" {
            val alias = Random.azString(32)
            val record = OpaqueIosAliasRecord(
                recordId = Random.azString(24),
                backendId = "com.example.crypto.test",
                representationVersion = 1,
                representation = byteArrayOf(4, 5, 6),
                publicKeySpki = byteArrayOf(0x30, 0x00),
                metadata = IosKeyMetadata(null, null, null),
                allowSigning = false,
            )
            try {
                IosKeychainProvider.storeOpaqueRecordForTest(alias, record, IosSigningKeyConfiguration())
                val duplicate = record.copy(recordId = "duplicate-record")
                runCatching { IosKeychainProvider.storeOpaqueRecordForTest(alias, duplicate, IosSigningKeyConfiguration()) }.isFailure shouldBe true
                val loaded = IosKeychainProvider.readOpaqueRecordForTest(alias)
                loaded?.backendId shouldBe record.backendId
                loaded?.recordId shouldBe record.recordId
                loaded?.representation?.contentEquals(record.representation) shouldBe true
                loaded?.publicKeySpki?.contentEquals(record.publicKeySpki) shouldBe true
                loaded?.allowSigning shouldBe false
                shouldThrow<UnsupportedCryptoException> { IosKeychainProvider.getSignerForKey(alias) }
                IosKeychainProvider.deleteSigningKey(alias)
                IosKeychainProvider.readOpaqueRecordForTest(alias) shouldBe null
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }

        "rolls back only the newly added record after a later failure" {
            val alias = Random.azString(32)
            val record = OpaqueIosAliasRecord(
                recordId = "owned-record", backendId = "com.example.rollback", representationVersion = 1,
                representation = byteArrayOf(1), publicKeySpki = byteArrayOf(0x30, 0x00),
                metadata = IosKeyMetadata(null, null, null), allowSigning = true,
            )
            runCatching {
                IosKeychainProvider.storeOpaqueRecordForTest(alias, record, IosSigningKeyConfiguration()) {
                    error("post-persist failure")
                }
            }.isFailure shouldBe true
            IosKeychainProvider.readOpaqueRecordForTest(alias) shouldBe null
        }
    }

    "opaque and SecKey aliases share a collision domain" - {
        "opaque record insertion rejects an existing SecKey alias without disturbing it" {
            val alias = Random.azString(32)
            try {
                val original = IosKeychainProvider.createSigningKey(alias)
                val record = OpaqueIosAliasRecord(
                    recordId = "collision-record", backendId = "com.example.collision", representationVersion = 1,
                    representation = byteArrayOf(2), publicKeySpki = byteArrayOf(0x30, 0x00),
                    metadata = IosKeyMetadata(null, null, null), allowSigning = true,
                )
                runCatching { IosKeychainProvider.storeOpaqueRecordForTest(alias, record, IosSigningKeyConfiguration()) }.isFailure shouldBe true
                IosKeychainProvider.getSignerForKey(alias).publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }
    }

    "exact backend routing constructs opaque signer without reopening" {
        val alias = Random.azString(32)
        val publicKey = with(EcdsaPublicKey) { ECCurve.SECP_256_R_1.generator.asPublicKey() }
        val record = createOpaqueAliasRecord(
            OpaqueAliasFixtureProvider.backendId,
            OpaqueIosKeyMaterial(byteArrayOf(9, 8, 7), publicKey),
            IosKeyMetadata(null, null, null),
        )
        ServiceLoader.register<IosKeychainOperationsProvider>(OpaqueAliasFixtureProvider)
        try {
            IosKeychainProvider.storeOpaqueRecordForTest(alias, record, IosSigningKeyConfiguration())
            val signer = IosKeychainProvider.getSignerForKey(alias)
            (signer is IosSigner.Opaque) shouldBe true
            signer.publicKey shouldBe publicKey
            signer.signatureAlgorithm shouldBe EcdsaAlgorithm(Digest.SHA256, publicKey.curve)
            OpaqueAliasFixtureProvider.reopenCount shouldBe 0
            runCatching { signer.sign(byteArrayOf(1, 2, 3)) }.isFailure shouldBe true
            OpaqueAliasFixtureProvider.reopenCount shouldBe 0
        } finally {
            IosKeychainProvider.deleteSigningKey(alias)
        }
    }

    "opaque record identity guard" - {
            "stale signer identity is rejected and missing backend aliases remain deletable" {
                val alias = Random.azString(32)
                val config = IosSigningKeyConfiguration()
                fun record(id: String) = OpaqueIosAliasRecord(
                    recordId = id, backendId = "com.example.missing.backend", representationVersion = 1,
                    representation = byteArrayOf(7), publicKeySpki = byteArrayOf(0x30, 0x00),
                    metadata = IosKeyMetadata(null, null, null), allowSigning = true,
                )
                try {
                    IosKeychainProvider.storeOpaqueRecordForTest(alias, record("record-one"), config)
                    IosKeychainProvider.requireCurrentOpaqueRecord(alias, "record-one")
                    IosKeychainProvider.deleteSigningKey(alias)
                    IosKeychainProvider.storeOpaqueRecordForTest(alias, record("record-two"), config)
                    runCatching { IosKeychainProvider.requireCurrentOpaqueRecord(alias, "record-one") }.isFailure shouldBe true
                    runCatching { IosKeychainProvider.getSignerForKey(alias) }.isFailure shouldBe true
                } finally {
                    IosKeychainProvider.deleteSigningKey(alias)
                }
                IosKeychainProvider.readOpaqueRecordForTest(alias) shouldBe null
            }
    }

    "Authentication timeout readback" - {
        data(
            listOf(null, Duration.ZERO, 10.seconds),
            nameFn = { it?.toString() ?: "no authentication" },
        ) test { authenticationTimeout ->
            val metadata = IosKeyMetadata(
                attestation = null,
                rawUnlockTimeout = authenticationTimeout,
                algSpecific = Json.encodeToJsonElement(IosKeyAlgSpecificMetadata.ECDSA(setOf(Digest.SHA256))),
            ).let { Json.decodeFromString<IosKeyMetadata>(Json.encodeToString(it)) }
            val publicKey = with(EcdsaPublicKey) {
                ECCurve.SECP_256_R_1.generator.asPublicKey()
            }
            val signer = IosSigner.ECDSA(
                alias = "restored-key",
                publicKey = publicKey,
                metadata = metadata,
                config = IosSignerConfiguration(),
            )

            signer.authenticationTimeout shouldBe authenticationTimeout
            signer.needsAuthentication shouldBe (authenticationTimeout != null)
            signer.needsAuthenticationForEveryUse shouldBe (authenticationTimeout == Duration.ZERO)
        }
    }

    "SecKey signer setup failure deletes only the generated key pair" {
        val alias = Random.azString(32)
        try {
            shouldThrow<IllegalStateException> {
                IosKeychainProvider.createSigningKey(alias) {
                    signer { error("signer setup failed after generation") }
                }
            }
            shouldThrow<NoSuchElementException> { IosKeychainProvider.getSignerForKey(alias) }
            IosKeychainProvider.createSigningKey(alias).alias shouldBe alias
        } finally {
            IosKeychainProvider.deleteSigningKey(alias)
        }
    }

    "Creating a key with an alias that already exists" - {

        "fails but leaves the existing key untouched when the new config is broken" {
            val alias = Random.azString(32)
            try {
                // an existing key lives under this alias
                val original = IosKeychainProvider.createSigningKey(alias)

                // attempt to create another key with the same alias, using a config that throws
                val secondAttempt = runCatching { IosKeychainProvider.createSigningKey(alias) {
                    throw IllegalStateException("intentionally broken config")
                }}
                secondAttempt.isFailure shouldBe true

                // the original key must still be present and unchanged
                IosKeychainProvider.getSignerForKey(alias).publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }

        "fails but leaves the existing key untouched when the new config is valid" {
            val alias = Random.azString(32)
            try {
                val original = IosKeychainProvider.createSigningKey(alias)

                val secondAttempt = runCatching { IosKeychainProvider.createSigningKey(alias) }
                secondAttempt.isFailure shouldBe true

                IosKeychainProvider.getSignerForKey(alias).publicKey shouldBe original.publicKey
            } finally {
                IosKeychainProvider.deleteSigningKey(alias)
            }
        }
    }
}
