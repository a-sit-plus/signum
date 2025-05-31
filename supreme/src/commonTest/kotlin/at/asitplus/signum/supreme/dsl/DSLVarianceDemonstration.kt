package at.asitplus.signum.supreme.dsl

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

private enum class Preparation { SHAKEN, STIRRED; }
/* all options classes need to inherit from DSL.Data */
private class Settings: DSL.Data() {
    /* we want you to choose a particular kind of smoothie flavor with particular parameters... */
    sealed class SmoothieFlavor constructor(): DSL.Data()
    class BananaFlavor(): SmoothieFlavor() {
        var preparation = Preparation.STIRRED
    }
    class StrawberryFlavor(): SmoothieFlavor() {
        var nBerries = 5
    }
    /* we define a holder that can hold any flavor */
    /* this is null by default; a default could be explicitly specified, making this non-nullable */
    val banana = firstOptionOfOptional(SmoothieFlavor::class, ::BananaFlavor)
    /* and then we define user-visible accessors for the different flavors */
    val strawberry = banana.alternate(::StrawberryFlavor)

    override fun validate() {
        require(banana.v != null)
            { "You need to choose a flavor!" }
    }
}

open class DSLVarianceDemonstration : FreeSpec({
    "\uD83D\uDE0A" {

        doWithConfiguration {
            banana {
                preparation = Preparation.SHAKEN
            }
        }

        doWithConfiguration {
            strawberry {
                nBerries = 202
            }
        }

        // this no longer works because we need to choose a flavor
        // we could've set a default flavor above and avoided this issue
        shouldThrow<IllegalArgumentException> { doWithConfiguration() }

    }
})

private fun doWithConfiguration(configure: (Settings.()->Unit)? = null) {
    val config = DSL.resolve(::Settings, configure)

    // we can access the result through any accessor
    // non-null was checked in the validator already
    when (val flavor = config.banana.v!!) {
        is Settings.BananaFlavor -> {
            flavor.preparation shouldBe Preparation.SHAKEN
        }
        is Settings.StrawberryFlavor -> {
            flavor.nBerries shouldBe 202
        }
    }
}
