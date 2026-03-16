package at.asitplus.signum.indispensable

import java.security.Signature

internal actual fun RsaSignatureAlgorithm.getRSAPlatformSignatureInstance(provider: String?): Signature =
    getJCASignatureInstance(provider).getOrThrow()
