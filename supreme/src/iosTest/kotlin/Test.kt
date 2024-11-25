package wumb

import at.asitplus.signum.indispensable.CryptoPrivateKey
import at.asitplus.signum.indispensable.SignatureAlgorithm
import at.asitplus.signum.indispensable.asn1.decodeFromPem
import at.asitplus.signum.indispensable.toSecKey
import at.asitplus.signum.supreme.sign.PrivateKeySigner
import at.asitplus.signum.supreme.sign.Signer
import at.asitplus.signum.supreme.sign.verifierFor
import at.asitplus.signum.supreme.sign.verify
import at.asitplus.signum.supreme.signature
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldNotBe
import kotlinx.cinterop.ExperimentalForeignApi

@OptIn(ExperimentalForeignApi::class)
class ProviderTest : FreeSpec({

    "This dummy test" {
        "is just making sure" shouldNotBe "that iOS tests are indeed running"
    }
})