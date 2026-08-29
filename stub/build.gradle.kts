// Compile-only stubs for hidden framework APIs the daemon calls (ActivityThread, ServiceManager,
// IPackageManager, SystemProperties, the keystore providers). These classes exist on the device at
// runtime; here they only satisfy the compiler and are never packaged (the app depends on this
// module with compileOnly).
plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

android {
    namespace = "org.matrix.teesim.stub"
    compileSdk = 36
    buildToolsVersion = "36.0.0"
    // Java-only: skip AGP's built-in Kotlin compilation and stdlib.
    enableKotlin = false
    defaultConfig { minSdk = 29 }

    buildTypes { release { isMinifyEnabled = false } }

    lint { abortOnError = false }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
}
