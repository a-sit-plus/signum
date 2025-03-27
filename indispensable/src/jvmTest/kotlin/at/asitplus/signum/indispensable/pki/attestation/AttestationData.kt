package at.asitplus.signum.indispensable.pki.attestation

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.CryptoPublicKey.Companion.decodeFromDer
import at.asitplus.signum.indispensable.toJcaPublicKey

import java.security.KeyFactory
import java.security.PublicKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.*


internal val certificateFactory = CertificateFactory.getInstance("X.509")
internal val mimeDecoder = Base64.getMimeDecoder()

internal val ecKeyFactory = KeyFactory.getInstance("EC")
internal val rsaKeyFactory = KeyFactory.getInstance("RSA")


class AttestationData(
    val name: String,
    challengeB64: String,
    val attestationProofB64: List<String>,
    isoDate: String,
    val pubKeyB64: String? = null,
    val packageName: String,
    val expectedDigest: ByteArray,
    val attestationLevel: Level = Level.HARDWARE
) {
    override fun toString() = "AttestationData($name)"

    enum class Level {
        HARDWARE,
        SOFTWARE,
        NOUGAT
    }

    enum class Level {
        HARDWARE, SOFTWARE, NOUGAT
    }

    val verificationDate: Date = Date.from(Instant.parse(isoDate))

    val challenge by lazy { mimeDecoder.decode(challengeB64) }

    val publicKey: PublicKey? by lazy {
        pubKeyB64?.let { CryptoPublicKey.decodeFromDer(mimeDecoder.decode(it)).toJcaPublicKey().getOrThrow() }
    }
}

val AttestationData.attestationCertChain: List<X509Certificate>
    get() = attestationProofB64.map {
        certificateFactory
            .generateCertificate(mimeDecoder.decode(it).inputStream()) as X509Certificate
    }
