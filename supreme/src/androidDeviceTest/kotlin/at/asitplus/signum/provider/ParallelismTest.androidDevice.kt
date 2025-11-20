package at.asitplus.signum.provider

import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.SigningProviderI

actual fun getTestProvider(): SigningProviderI<*, *, *> = PlatformSigningProvider