package at.asitplus.signum.internals

val isAndroid by lazy {
    try {
        Class.forName("android.os.Build"); true
    } catch (_: ClassNotFoundException) {
        false
    }
}

