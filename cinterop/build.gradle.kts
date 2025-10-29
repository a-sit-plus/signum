plugins {
    base
}
// Adapted from https://github.com/openwallet-foundation/multipaz
listOf("iphoneos", "iphonesimulator").forEach { sdk ->
    val taskName = "build${sdk.replaceFirstChar { it.titlecase() }}"

    tasks.register<Exec>(taskName) {
        group = "build"
        workingDir = projectDir

        commandLine(
            "xcodebuild",
            "-project", "AESwift.xcodeproj",
            "-scheme", "AESwift",
            "-sdk", sdk,
            "-configuration", "Release",
            "SYMROOT=${projectDir}/build"
        )

        inputs.files(
            fileTree("$projectDir/AESwift.xcodeproj") { exclude("**/xcuserdata") },
            fileTree("$projectDir/AESwift")
        )
        outputs.files(
            fileTree("$projectDir/build/Release-${sdk}")
        )
    }
}