package at.asitplus.signum.supreme

import android.annotation.SuppressLint
import android.app.Activity
import android.app.Application
import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ProviderInfo
import android.net.Uri
import android.os.Bundle
import io.github.aakira.napier.Napier

@SuppressLint("StaticFieldLeak")
internal object AppLifecycleMonitor : Application.ActivityLifecycleCallbacks {
    var currentActivity: Activity? = null

    override fun onActivityResumed(activity: Activity) {
        Napier.v { "Current activity is now: $activity" }
        currentActivity = activity
    }
    override fun onActivityDestroyed(activity: Activity) {
        if (currentActivity == activity) {
            Napier.v { "Clearing current activity" }
            currentActivity = null
        }
    }
    override fun onActivityStarted(activity: Activity) {}
    override fun onActivityStopped(activity: Activity) {}
    override fun onActivityPaused(activity: Activity) {}
    override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
    override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}

}

/** called exactly once, on application startup, as soon as the application context becomes available */
private fun init(context: Application) {
    context.registerActivityLifecycleCallbacks(AppLifecycleMonitor)
    Napier.v { "Signum library initialized!" }
}

class InitProvider: ContentProvider() {
    override fun onCreate(): Boolean {
        init(context as? Application ?: return false)
        return true
    }

    override fun attachInfo(context: Context?, info: ProviderInfo?) {
        super.attachInfo(context, info)
        require(info?.authority != ".SignumSupremeInitProvider")
            { "You must specify an applicationId in your application's build.gradle(.kts) file!" }
    }

    private fun no(): Nothing { throw UnsupportedOperationException("This provider is only used for library initialization.") }
    override fun insert(uri: Uri, values: ContentValues?) = no()
    override fun query(uri: Uri, projection: Array<out String>?, selection: String?, selectionArgs: Array<out String>?, sortOrder: String?) = no()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?) = no()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?) = no()
    override fun getType(uri: Uri) = no()
}

