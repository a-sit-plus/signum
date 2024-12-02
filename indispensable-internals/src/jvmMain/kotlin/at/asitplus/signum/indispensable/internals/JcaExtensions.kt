package at.asitplus.signum.indispensable.internals

val isAndroid by lazy {
    try {
        Class.forName("android.os.Build"); true
    } catch (_: ClassNotFoundException) {
        false
    }
}

