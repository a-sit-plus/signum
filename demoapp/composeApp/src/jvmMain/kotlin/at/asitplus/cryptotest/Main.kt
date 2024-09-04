package at.asitplus.cryptotest

import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import at.asitplus.signum.supreme.os.JKSProvider
import at.asitplus.signum.supreme.os.SigningProvider

actual val Provider: SigningProvider = JKSProvider.Ephemeral().getOrThrow()

fun main() = application {
    Window(onCloseRequest = ::exitApplication, title = "Supreme Demo") {
        App()
    }
}