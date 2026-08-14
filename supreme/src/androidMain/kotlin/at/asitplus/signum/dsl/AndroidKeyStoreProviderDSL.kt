package at.asitplus.signum.dsl

val AndroidSigningKeyConfiguration.hardware get() =
    childOrNull("HARDWARE", ::AndroidKeymasterConfiguration)

val AndroidSignerConfiguration.unlockPrompt get() =
    childOrDefault("UNLOCK_PROMPT", ::AndroidUnlockPromptConfiguration)

val AndroidSignerSigningConfiguration.unlockPrompt get() =
    childOrDefault("UNLOCK_PROMPT", ::AndroidUnlockPromptConfiguration)
