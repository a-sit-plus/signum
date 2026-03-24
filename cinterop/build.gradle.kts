plugins {
    base
}
// Adapted from https://github.com/openwallet-foundation/multipaz
listOf("iphoneos", "iphonesimulator").forEach { sdk ->
    val taskName = "build${sdk.replaceFirstChar { it.titlecase() }}"
    val destination = when (sdk) {
        "iphoneos" -> "generic/platform=iOS"
        "iphonesimulator" -> "generic/platform=iOS Simulator"
        else -> error("Unsupported Apple SDK: $sdk")
    }

    tasks.register<Exec>(taskName) {
        group = "build"
        workingDir = projectDir

        commandLine(
            "xcodebuild",
            "-project", "AESwift.xcodeproj",
            "-scheme", "AESwift",
            "-sdk", sdk,
            "-destination", destination,
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
