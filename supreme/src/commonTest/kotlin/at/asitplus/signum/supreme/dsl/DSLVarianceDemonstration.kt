package at.asitplus.signum.supreme.dsl

import io.kotest.assertions.throwables.shouldThrow
import at.asitplus.testballoon.matrix.*
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
    val _flavor get() = subclassOf<SmoothieFlavor>("FLAVOR")
    /* and then we define user-visible accessors for the different flavors */
    val banana get() = _flavor.option("BANANA", ::BananaFlavor)
    val strawberry get() = _flavor.option("STRAWBERRY", ::StrawberryFlavor)

    override fun validate() {
        require(_flavor.isSet)
            { "You need to choose a flavor!" }
    }
}

val DSLVarianceDemonstration  by matrixSuite {
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
}

private fun doWithConfiguration(configure: (Settings.()->Unit)? = null) {
    val config = DSL.resolve(::Settings, configure)

    // we can access the result through the accessors, or use the helper
    when (val flavor = DSL.options(config.banana, config.strawberry)) {
        is Settings.BananaFlavor -> {
            flavor.preparation shouldBe Preparation.SHAKEN
        }
        is Settings.StrawberryFlavor -> {
            flavor.nBerries shouldBe 202
        }
        // non-null was checked in the validator already
        null -> error("unreachable")
    }
}
