pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "TEESimulator"

// The compile-only framework stubs (hidden platform APIs), then the daemon itself
// (which also drives the native interceptor build and module packaging).
include(":stub")

include(":app")
