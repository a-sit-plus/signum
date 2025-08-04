package at.asitplus.signum

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.ECCurve
import at.asitplus.signum.indispensable.SecretExposure
import at.asitplus.signum.indispensable.asymmetric.AsymmetricEncryptionAlgorithm
import at.asitplus.signum.indispensable.misc.BitLength
import at.asitplus.signum.indispensable.misc.bit
import at.asitplus.signum.indispensable.pki.attestation.AuthorizationList
import at.asitplus.signum.indispensable.pki.attestation.KeyDescription
import at.asitplus.signum.indispensable.pki.attestation.SecureKeyWrapper
import at.asitplus.signum.indispensable.symmetric.*
import at.asitplus.signum.supreme.asymmetric.encryptorFor
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.symmetric.encrypt
import io.kotest.core.spec.style.FreeSpec
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security
import kotlin.time.Duration.Companion.seconds


@OptIn(SecretExposure::class)
class SecureKeyWrapperTest : FreeSpec({
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

        //TODO make this into an instrumented test that acutally imports a key, does some magic with teh private key
        // and then use the key material to verify
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

@OptIn(SecretExposure::class)
@Throws(Exception::class)
suspend fun wrapKey(
    publicKey: CryptoPublicKey, keyMaterial: CryptoPrivateKey,
    authorizationList: AuthorizationList
): SecureKeyWrapper {

    // Build description
    val descriptionItems = KeyDescription(KeyDescription.KeyFormat.PKCS8, authorizationList)

    // Generate 256 bit AES key. This is the ephemeral key used to encrypt the secure key.
    val randomKey = SymmetricEncryptionAlgorithm.AES_256.GCM.randomKey()
    val aesKeyBytes = randomKey.secretKey.getOrThrow()

    val encryptor = AsymmetricEncryptionAlgorithm.RSA.OAEP.SHA256.encryptorFor(publicKey)
    val encryptedEphemeralKeys = encryptor.encrypt(aesKeyBytes).getOrThrow()

    // Encrypt secure key
    val encryptedSecureKey =
        randomKey.encrypt(data = keyMaterial.encodeToDer(), authenticatedData = descriptionItems.encodeToDer())
            .getOrThrow()

    // Build ASN.1 DER encoded sequence WrappedKeyWrapper
    return SecureKeyWrapper(
        encryptedTransportKey = encryptedEphemeralKeys,
        initializationVector = encryptedSecureKey.nonce,
        keyDescription = descriptionItems,
        secureKey = encryptedSecureKey.encryptedData,
        tag = encryptedSecureKey.authTag
    )

}