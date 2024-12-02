package at.asitplus.signum.indispensable.internals


infix fun <T: Any> T?.orLazy(block: ()->T) =    if (this != null) lazyOf(this) else lazy(block)
