package at.asitplus.cryptotest

import android.app.Application
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity

class AppActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            App()
        }
    }
}
