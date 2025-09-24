## The Test Dance

### Why Dance?

The KMP+Android Gradle plugin combination appears broken.

To reproduce in project "indispensable":

1. `gradlew -p indispensable clean testReleaseUnitTest`
    > Plugin de.infix.testBalloon: Could not find function 'de.infix.testBalloon.framework.internal.configureAndExecuteTests'.
2. `gradlew -p indispensable clean testReleaseUnitTest -Plocal.androidUnitTestDance=removeDependency`
    > [from build scan] org.junit.platform.commons.PreconditionViolationException: Cannot create Launcher without at least one TestEngine; consider adding an engine implementation JAR to the classpath
3. `gradlew -p indispensable testReleaseUnitTest`
    > works, 6550 tests passed


### Running All Tests

1. `gradlew clean testDebugUnitTest testReleaseUnitTest -Plocal.androidUnitTestDance=removeDependency --continue`
2. `gradlew testDebugUnitTest testReleaseUnitTest --continue`
3. `gradlew allTests --continue`
