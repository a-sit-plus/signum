package at.asitplus.cryptotest

import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.SigningProvider

actual val Provider: SigningProvider = PlatformSigningProvider
