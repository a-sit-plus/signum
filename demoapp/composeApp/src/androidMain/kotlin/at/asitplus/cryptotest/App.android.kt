package at.asitplus.cryptotest

import android.app.Application
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import at.asitplus.signum.supreme.os.PlatformSigningProvider
import at.asitplus.signum.supreme.os.SigningProvider

actual val Provider: SigningProvider = PlatformSigningProvider

class AndroidApp : Application()

class AppActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            App()
        }
    }
}
