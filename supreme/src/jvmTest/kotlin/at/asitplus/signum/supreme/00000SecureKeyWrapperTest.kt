package at.asitplus.signum

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.attestation.AuthorizationList
import at.asitplus.signum.indispensable.pki.attestation.KeyDescription
import at.asitplus.signum.indispensable.pki.attestation.SecureKeyWrapper
import at.asitplus.signum.indispensable.toJcaPublicKey
import at.asitplus.signum.supreme.sign.Signer
import io.kotest.core.spec.style.FreeSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import java.security.spec.MGF1ParameterSpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random
import kotlin.time.Duration.Companion.seconds


@OptIn(SecretExposure::class)
class `0000000SecureKeyWrapperTest` : FreeSpec({
    Security.addProvider(BouncyCastleProvider())

    "mock tests" {
        val mockAndroid = Signer.Ephemeral {
            rsa {
            }
        }

        val mockServer = Signer.Ephemeral {
            ec {
                curve = ECCurve.SECP_256_R_1
            }
        }

        val securedKey = wrapKey(
            mockAndroid.getOrThrow().publicKey,
            mockServer.getOrThrow().exportPrivateKey().getOrThrow(),
            makeEcAuthList(256.bit)
        )

        println(securedKey.encodeToTlv().prettyPrint())
    }
})


private fun makeEcAuthList(size: BitLength): AuthorizationList {
    val purposes = setOf(
        AuthorizationList.KeyPurpose.DERIVE_KEY,
        AuthorizationList.KeyPurpose.SIGN,
        AuthorizationList.KeyPurpose.VERIFY
    )
    val algorithm = AuthorizationList.Algorithm.EC
    val keySize = AuthorizationList.KeySize((size))

    val digests = setOf(AuthorizationList.Digest.SHA_2_256)
    return AuthorizationList(
        purpose = purposes,
        algorithm = algorithm,
        keySize = keySize,
        digest = digests,
        userAuthType = AuthorizationList.UserAuthType.FINGERPRINT,
        authTimeout = AuthorizationList.AuthTimeout(5.seconds),
        attestationVersion = null
    )
}

@Throws(Exception::class)
fun wrapKey(
    publicKey: CryptoPublicKey, keyMaterial: CryptoPrivateKey,
    authorizationList: AuthorizationList
): SecureKeyWrapper {
    // Build description


    val descriptionItems = KeyDescription(KeyDescription.KeyFormat.PKCS8, authorizationList)

    // Generate 12 byte initialization vector
    val iv = ByteArray(12)
    Random.nextBytes(iv)
    // Generate 256 bit AES key. This is the ephemeral key used to encrypt the secure key.
    val aesKeyBytes = ByteArray(32)
    Random.nextBytes(aesKeyBytes)
    // Encrypt ephemeral keys
    val spec =
        OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT
        )
    val pkCipher = Cipher.getInstance("RSA/ECB/OAEPPadding")
    pkCipher.init(Cipher.ENCRYPT_MODE, publicKey.toJcaPublicKey().getOrThrow(), spec)
    val encryptedEphemeralKeys = pkCipher.doFinal(aesKeyBytes)
    // Encrypt secure key
    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
    val secretKeySpec = SecretKeySpec(aesKeyBytes, "AES")
    val gcmParameterSpec = GCMParameterSpec(128, iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec)
    val aad: ByteArray = descriptionItems.encodeToDer()
    cipher.updateAAD(aad)
    var encryptedSecureKey = cipher.doFinal(keyMaterial.encodeToDer())
    // Get GCM tag. Java puts the tag at the end of the ciphertext data :(
    val len = encryptedSecureKey.size
    val tagSize: Int = (128 / 8)
    val tag: ByteArray = Arrays.copyOfRange(encryptedSecureKey, len - tagSize, len)
    // Remove GCM tag from end of output
    encryptedSecureKey = Arrays.copyOfRange(encryptedSecureKey, 0, len - tagSize)
    // Build ASN.1 DER encoded sequence WrappedKeyWrapper
    return SecureKeyWrapper(
        encryptedTransportKey = encryptedEphemeralKeys,
        initializationVector = iv,
        keyDescription = descriptionItems,
        secureKey = encryptedSecureKey,
        tag = tag
    )

}