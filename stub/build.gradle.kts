plugins {
  alias(libs.plugins.android.library)
  alias(libs.plugins.ktfmt)
}

android {
  namespace = "org.matrix.stub"
  compileSdk = 36
  buildToolsVersion = "36.0.0"
  // This module is Java-only, so skip AGP's built-in Kotlin compilation and stdlib.
  enableKotlin = false
  defaultConfig { minSdk = 29 }

  buildTypes { release { isMinifyEnabled = false } }

  lint { abortOnError = true }
  compileOptions {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
  }
}

dependencies { compileOnly(libs.annotation) }
