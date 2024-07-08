package at.asitplus.crypto.provider.os

import at.asitplus.crypto.datatypes.CryptoPublicKey
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.types.shouldBeInstanceOf

class iosKeychainProviderTests : FreeSpec({
    "it works" {
        IosKeychainProvider.createSigningKey("Bartschloss").getOrThrow().shouldBeInstanceOf<CryptoPublicKey.EC>()
    }
})
