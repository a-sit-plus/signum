package at.asitplus.cryptotest

import android.app.Application
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.ui.platform.LocalContext
import androidx.fragment.app.FragmentActivity
import at.asitplus.signum.supreme.os.AndroidKeyStoreProvider
import at.asitplus.signum.supreme.os.SigningProvider


class AndroidApp : Application() {
    companion object {
        lateinit var INSTANCE: AndroidApp
    }

    override fun onCreate() {
        super.onCreate()
        INSTANCE = this
    }
}

private lateinit var fragmentActivity: FragmentActivity

class AppActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            App()
            fragmentActivity = LocalContext.current as FragmentActivity
        }
    }
}

internal actual fun getSystemKeyStore(): SigningProvider =
    AndroidKeyStoreProvider()
