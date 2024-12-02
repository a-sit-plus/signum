package at.asitplus.signum.indispensable

val isAndroid by lazy {
    try {
        Class.forName("android.os.Build"); true
    } catch (_: ClassNotFoundException) {
        false
    }
}

