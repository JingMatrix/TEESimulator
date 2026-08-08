import com.ncorti.ktfmt.gradle.tasks.KtfmtFormatTask

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.ktfmt) apply true
}

tasks.register<KtfmtFormatTask>("format") {
    source = project.fileTree(rootDir)
    include("*.gradle.kts", "*/*.gradle.kts")
    dependsOn(":stub:ktfmtFormat")
    dependsOn(":app:ktfmtFormat")
}

ktfmt { kotlinLangStyle() }
