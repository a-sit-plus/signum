package at.asitplus.signum

class ImplementationError(message: String?=null): Throwable("$message\nThis is an implementation error. Please report this bug at https://github.com/a-sit-plus/signum/issues/new/")