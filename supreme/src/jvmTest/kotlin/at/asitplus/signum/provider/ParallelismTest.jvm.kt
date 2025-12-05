package at.asitplus.signum.provider

import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.os.SigningProviderI

actual fun getTestProvider(): SigningProviderI<*, *, *> = JKSProvider.Ephemeral().getOrThrow()