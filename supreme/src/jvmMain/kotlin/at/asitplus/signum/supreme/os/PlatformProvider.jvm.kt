package at.asitplus.signum.supreme.os

import at.asitplus.signum.dsl.PlatformSigningProviderConfigurationBase
import at.asitplus.signum.supreme.dsl.DSLConfigureFn

internal actual fun getPlatformSigningProvider(configure: DSLConfigureFn<PlatformSigningProviderConfigurationBase>): PlatformSigningProviderI<*,*,*> =
    throw UnsupportedOperationException("No default persistence mode is available on the JVM. Use JKSProvider {file {}} or similar. This will be natively available from the getPlatformSigningProvider {} DSL in a future release. (Blocked by KT-71036.)")
