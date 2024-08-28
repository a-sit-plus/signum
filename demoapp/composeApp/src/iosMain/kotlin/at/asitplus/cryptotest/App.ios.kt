package at.asitplus.cryptotest

import at.asitplus.signum.supreme.os.IosKeychainProvider
import at.asitplus.signum.supreme.os.SigningProvider

internal actual fun getSystemKeyStore(): SigningProvider = IosKeychainProvider
