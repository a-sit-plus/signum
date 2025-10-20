package at.asitplus.signum.test


import io.github.classgraph.ClassGraph

inline fun <reified T : Any> findImplementations(): List<Class<out T>> {
    ClassGraph()
        .enableClassInfo()
        .enableExternalClasses()
        .acceptPackages("") // or restrict: "com.example"
        .scan().use { scanResult ->
            return scanResult.getClassesImplementing(T::class.java.name)
                .filter { !it.isAbstract && !it.isInterface }
                .loadClasses(T::class.java)
        }
}