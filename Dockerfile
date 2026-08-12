FROM eclipse-temurin:17-jdk AS build

WORKDIR /workspace

ARG ANDROID_COMPILE_SDK=34
ARG ANDROID_BUILD_TOOLS=34.0.0
ARG ANDROID_TEST_API=35
ARG ANDROID_CMDLINE_TOOLS_VERSION=11076708
ARG KOTLIN_REPO_URL
ARG KOTLIN_VERSION
ARG KOTLIN_API_VERSION
ARG KOTLIN_LANGUAGE_VERSION
ARG KOTLIN_ADDITIONAL_CLI_OPTIONS
ARG TESTBALLOON_VERSION

ENV ANDROID_HOME=/opt/android-sdk
ENV ANDROID_SDK_ROOT=${ANDROID_HOME}
ENV PATH=${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:${PATH}

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends libatomic1 unzip wget; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p "${ANDROID_HOME}/cmdline-tools"; \
    wget -q "https://dl.google.com/android/repository/commandlinetools-linux-${ANDROID_CMDLINE_TOOLS_VERSION}_latest.zip" -O /tmp/android-commandlinetools.zip; \
    unzip -q /tmp/android-commandlinetools.zip -d "${ANDROID_HOME}/cmdline-tools"; \
    mv "${ANDROID_HOME}/cmdline-tools/cmdline-tools" "${ANDROID_HOME}/cmdline-tools/latest"; \
    rm /tmp/android-commandlinetools.zip; \
    yes | sdkmanager --licenses > /dev/null; \
    sdkmanager "platform-tools" "platforms;android-${ANDROID_COMPILE_SDK}" "build-tools;${ANDROID_BUILD_TOOLS}"
# Add `"emulator" "system-images;android-${ANDROID_TEST_API};aosp_atd;x86_64"` to sdkmanager when pixelAVDAndroidDeviceTest runs below; downloading it otherwise makes no sense.

COPY . .

RUN chmod +x ./gradlew; \
    printf 'sdk.dir=%s\n' "${ANDROID_HOME}" > local.properties

RUN set -eux; \
#    android device tests cannot run inside docker, so we only run jvm tests. this misses quite a chunk of coverage
#    set -- allTests pixelAVDAndroidDeviceTest --no-daemon; \
    set -- --no-daemon; \
    if [ -n "${KOTLIN_REPO_URL:-}" ]; then set -- "$@" "-Pkotlin_repo_url=${KOTLIN_REPO_URL}"; fi; \
    if [ -n "${KOTLIN_API_VERSION:-}" ]; then set -- "$@" "-Pkotlin_api_version=${KOTLIN_API_VERSION}"; fi; \
    if [ -n "${KOTLIN_LANGUAGE_VERSION:-}" ]; then set -- "$@" "-Pkotlin_language_version=${KOTLIN_LANGUAGE_VERSION}"; fi; \
    if [ -n "${KOTLIN_ADDITIONAL_CLI_OPTIONS:-}" ]; then set -- "$@" "-Pkotlin_additional_cli_options=${KOTLIN_ADDITIONAL_CLI_OPTIONS}"; fi; \
    ./gradlew kotlinUpgradeYarnLock "$@"; \
    ./gradlew allTests "$@"
