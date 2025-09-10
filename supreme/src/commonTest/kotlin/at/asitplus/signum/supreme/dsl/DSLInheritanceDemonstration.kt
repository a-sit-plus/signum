package at.asitplus.signum.supreme.dsl

import io.kotest.assertions.fail
import io.kotest.core.spec.style.FreeSpec
import io.kotest.matchers.shouldBe

/* All options classes need to inherit from DSL.Data; it is also annotated with a DSL marker */
private open class GenericOptions(): DSL.Data() {
    var genericSimpleValue: String = "default value"

    open class GenericSubOptions(): DSL.Data() {
        var genericSubValue: Int = 42
    }
    /* expose GenericSubOptions as a nested DSL child */
    open val subValue = childOrDefault(::GenericSubOptions)
}

/* This is a more specific version of GenericOptions */
private class SpecificOptions(): GenericOptions() {
    init {
        genericSimpleValue = "overridden default value"
    }
    var specificSimpleValue: String = "another default value"

    class SpecificSubOptions(): GenericSubOptions() {
        var anotherSpecificSubValue: String? = null
    }
    /* this shadows the subValue member on the superclass with a more specific version */
    override val subValue = childOrDefault(::SpecificSubOptions)
}

open class DSLInheritanceDemonstration : FreeSpec({
    "\uD83D\uDE0A" {
        /* if we have the necessary type information, we know that it's a specific DSL subclass... */
        doWithConfiguration {
            /* ... and can access all of the members */
            genericSimpleValue = "why hello there..."
            specificSimpleValue = "general DSL!"

            subValue {
                genericSubValue = 21
                anotherSpecificSubValue = "freaky!"
            }
        }

        /* but if we don't know that it's this specific kind of class ... */
        val doWithGenericConfiguration: (((GenericOptions.() -> Unit)?) -> Unit) =
            ::doWithConfiguration

        doWithGenericConfiguration {
            /* ... we can still access the generic options */
            genericSimpleValue = "straight ahead!"
            subValue {
                genericSubValue = 23
            }
        }

        /* this also works btw */
        doWithConfiguration()
    }
})

private fun doWithConfiguration(configure: (SpecificOptions.()->Unit)? = null) {
    /* resolve the configuration lambda to a concrete configuration object */
    val config = DSL.resolve(::SpecificOptions, configure)
    /* and check the values we set */
    when (config.subValue.v.genericSubValue) {
        42 -> { /* no-arg invocation, all values default */
            config.genericSimpleValue shouldBe "overridden default value"
            config.specificSimpleValue shouldBe "another default value"
            config.subValue.v.anotherSpecificSubValue shouldBe null
        }
        21 -> { /* specific invocation */
            config.genericSimpleValue shouldBe "why hello there..."
            config.specificSimpleValue shouldBe "general DSL!"
            config.subValue.v.anotherSpecificSubValue shouldBe "freaky!"
        }
        23 -> { /* generic invocation */
            config.genericSimpleValue shouldBe "straight ahead!"
            config.specificSimpleValue shouldBe "another default value"
            config.subValue.v.anotherSpecificSubValue shouldBe null
        }
        else -> fail("Unexpected generic subvalue")
    }
}
