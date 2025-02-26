package at.asitplus.signum.indispensable

@RequiresOptIn(message = "Access to secret and private key material requires explicit opt-in. Specify @OptIn(SecretExposure::class). Make sure that you actually want to externalise a secret. Check yourself, before you really, really, wreck yourself!")
/** This guards a secret. Do not expose it lightly! */
annotation class SecretExposure
