import at.asitplus.crypto.datatypes.CryptoPublicKey
import at.asitplus.crypto.datatypes.SignatureAlgorithm
import at.asitplus.crypto.datatypes.pki.X509Certificate
import at.asitplus.crypto.provider.sign.verifierFor
import at.asitplus.crypto.provider.sign.verify
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.compilation.shouldCompile

class ReadmeCompileTest : FreeSpec({
    "Signature Verification" {
"""
val publicKey: CryptoPublicKey.EC = TODO("You have this and trust it.")
val plaintext = "You want to trust this.".encodeToByteArray()
val signature = TODO("This was sent alongside the plaintext.")
val verifier = SignatureAlgorithm.ECDSAwithSHA256.verifierFor(publicKey).getOrThrow()
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Looks good? %isValid")
""".replace('%','$').shouldCompile()
    }
    "X509 Signature Verification" {
"""
val rootCert: X509Certificate = TODO("You have this and trust it.")
val untrustedCert: X509Certificate = TODO("You want to verify that this is trustworthy.")

val verifier = untrustedCert.signatureAlgorithm.verifierFor(rootCert.publicKey).getOrThrow()
val plaintext = untrustedCert.tbsCertificate.encodeToDer()
val signature = untrustedCert.signature
val isValid = verifier.verify(plaintext, signature).isSuccess
println("Certificate looks trustworthy: %isValid")
""".replace('%','$').shouldCompile()
    }
})
