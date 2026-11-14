package at.asitplus.signum.test

import java.io.File
import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader

/** Runs a static scenario with fresh library globals; mutations cannot leak into other tests. */
fun isolatedScenario(scenarioClass: Class<*>, method: String, vararg arguments: String) {
    val urls = System.getProperty("java.class.path").split(File.pathSeparator)
        .map { File(it).toURI().toURL() }.toTypedArray()
    URLClassLoader(urls, ClassLoader.getPlatformClassLoader()).use { loader ->
        try {
            loader.loadClass(scenarioClass.name)
                .getMethod(method, *Array(arguments.size) { String::class.java })
                .invoke(null, *arguments)
        } catch (exception: InvocationTargetException) {
            throw exception.targetException
        }
    }
}
