package at.asitplus.signum.dsl

import at.asitplus.signum.supreme.os.AndroidKeymasterConfiguration
import at.asitplus.signum.supreme.os.AndroidSignerConfiguration
import at.asitplus.signum.supreme.os.AndroidSignerSigningConfiguration
import at.asitplus.signum.supreme.os.AndroidSigningKeyConfiguration
import at.asitplus.signum.supreme.os.AndroidUnlockPromptConfiguration

val AndroidSigningKeyConfiguration.hardware get() =
    childOrNull("HARDWARE", ::AndroidKeymasterConfiguration)

val AndroidSignerConfiguration.unlockPrompt get() =
    childOrDefault("UNLOCK_PROMPT", ::AndroidUnlockPromptConfiguration)

val AndroidSignerSigningConfiguration.unlockPrompt get() =
    childOrDefault("UNLOCK_PROMPT", ::AndroidUnlockPromptConfiguration)
