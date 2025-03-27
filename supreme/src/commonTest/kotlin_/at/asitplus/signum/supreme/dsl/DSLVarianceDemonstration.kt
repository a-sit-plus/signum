package at.asitplus.signum.supreme.dsl

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

private enum class Preparation { SHAKEN, STIRRED; }
/* all options classes need to inherit from DSL.Data */
private class Settings: DSL.Data() {
    /* we want you to choose a particular kind of smoothie flavor with particular parameters... */
    sealed class SmoothieFlavor constructor(): DSL.Data()
    class BananaFlavor internal constructor(): SmoothieFlavor() {
        var preparation = Preparation.STIRRED
    }
    class StrawberryFlavor internal constructor(): SmoothieFlavor() {
        var nBerries = 5
    }
    /* we define a holder that can hold any flavor */
    /* "internal" because the generic accessor shouldn't be visible to users */
    /* this is null by default; a default could be explicitly specified, making this non-nullable */
    internal val _flavor = subclassOf<SmoothieFlavor>()
    /* and then we define user-visible accessors for the different flavors */
    val banana = _flavor.option(::BananaFlavor)
    val strawberry = _flavor.option(::StrawberryFlavor)

    override fun validate() {
        require(_flavor.v != null)
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

    // we can access the result through the generic accessor
    // non-null was checked in the validator already
    when (val flavor = config._flavor.v!!) {
        is Settings.BananaFlavor -> {
            flavor.preparation shouldBe Preparation.SHAKEN
        }
        is Settings.StrawberryFlavor -> {
            flavor.nBerries shouldBe 202
        }
    }
}
