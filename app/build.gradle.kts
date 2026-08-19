// The TEESimulator control daemon plus the native interceptors and module packaging.
//
// Built as an Android application so AGP's R8 pass shrinks the bundled BouncyCastle
// down to a single classes.dex (app_process runs that dex at boot). The C/C++
// interceptors (inject, teesim_keymint, teesim_keystore) build through AGP's
// externalNativeBuild against the repo-root CMakeLists.txt, which also drives the
// Rust TA (rust/build.sh) via its rust_ta target and links a self-contained static
// BoringSSL. Packaging mirrors both build variants: `prepareModuleFiles<Variant>`
// stages the payload (Release: the R8 dex; Debug: the signed APK as service.apk),
// the stripped native interceptors and the injector, and the module/ tree; then
// `zip<Variant>` assembles the flashable module into out/.
import com.android.build.api.artifact.SingleArtifact
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

// Helper class to get access to the ExecOperations service for git queries.
abstract class GitExecutor @Inject constructor(private val execOperations: ExecOperations) {
    fun execute(command: String, currentWorkingDir: File): String {
        val byteOut = ByteArrayOutputStream()
        execOperations.exec {
            workingDir = currentWorkingDir
            commandLine = command.split("\\s".toRegex())
            standardOutput = byteOut
        }
        return String(byteOut.toByteArray()).trim()
    }
}

val gitExecutor = objects.newInstance(GitExecutor::class.java)
val gitCommitCount = gitExecutor.execute("git rev-list HEAD --count", rootDir).toInt()
val gitCommitHash = gitExecutor.execute("git rev-parse --verify --short HEAD", rootDir)
val verName = "v4.0"

android {
    namespace = "org.matrix.teesim"
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.matrix.teesim"
        minSdk = 29
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = verName
        externalNativeBuild {
            cmake {
                // The interceptors are 64-bit only (keystore2 is 64-bit everywhere).
                abiFilters += listOf("arm64-v8a", "x86_64")
                // Match package.sh: build the injector and both interceptors; the
                // static BoringSSL `crypto` target builds transitively for keystore.
                targets += listOf("inject", "teesim-uds", "teesim_keymint", "teesim_keystore")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
            signingConfig = null
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    // No BuildConfig/resources: this is a headless dex, not an app.
    buildFeatures {
        buildConfig = false
        resValues = false
    }

    // R8 shrinking pulls in mergeReleaseJavaResource, and three BouncyCastle jars
    // (bcpkix/bcutil/bcprov, all 1.85) each ship an identical META-INF/LICENSE.md,
    // which fails the merge. We extract only classes.dex, so the resource is never
    // packaged anyway — drop it to let the merge pass.
    packaging {
        resources { excludes += "META-INF/LICENSE.md" }
        // Keep the interceptor's symbols so a native/TA crash symbolicates to file:line in the
        // tombstone (paired with the Rust profile's debug=true). AGP otherwise strips them, and the
        // module packaging reads the stripped output.
        jniLibs { keepDebugSymbols += "**/libteesim_keymint.so" }
    }

    lint { abortOnError = false }

    externalNativeBuild {
        cmake {
            path = rootProject.file("CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    // Full BouncyCastle: Android ships only a stripped "BC" provider, so we bundle
    // and swap in the complete library for ASN.1 parsing of the attestation record.
    implementation(libs.bcpkix)
}

// Extract classes.dex from the R8-shrunken release output into build/teesim/.
// app_process runs this dex directly. Sourced from the R8 intermediate (not the
// packaged APK) so a plain `:app:dex` does not drag in the native build.
tasks.register<Copy>("dex") {
    group = "teesim"
    description = "Builds the daemon and copies classes.dex to build/teesim/."
    dependsOn("minifyReleaseWithR8")
    from(layout.buildDirectory.dir("intermediates/dex/release/minifyReleaseWithR8")) {
        include("classes.dex")
    }
    into(layout.buildDirectory.dir("teesim"))
}

// --- Module packaging -------------------------------------------------------
// Assemble the flashable module, once per build variant, from three ingredients:
// the daemon payload (Release: the R8-shrunken classes.dex that app_process runs
// at boot; Debug: the signed APK renamed service.apk, which module/daemon uses as
// a classpath fallback), the stripped interceptor libraries plus the injector
// executable (AGP's per-variant native build), and the module/ tree (scripts +
// WebUI). The interceptors are 64-bit only, so binaries live under <abi>/ at the
// module root, exactly where module/daemon and module/customize.sh expect them.

// Per-root-manager install tasks target adb. When several devices are attached, pick
// one with adb's own ANDROID_SERIAL env var — the Exec tasks inherit it, so
//     ANDROID_SERIAL=<serial> ./gradlew installKsuAndRebootDebug
// targets that device with no extra flags.
fun adb(vararg args: String): List<String> = listOf("adb", *args)

// Syntax-check the WebUI JavaScript before packaging it. The WebUI is a set of ES modules; a single
// syntax error makes one module fail to parse, its importers fail with it, and the whole UI never
// renders (health stuck "checking", every page blank) — a failure the Kotlin/native build cannot catch.
// This runs `node --check` on every module/webroot JS file, but only when node is installed: a build on
// a machine without node logs a notice and proceeds, so node is a convenience, not a hard requirement.
val checkWebrootJs =
    tasks.register("checkWebrootJs") {
        group = "TEESimulator Module Packaging"
        description = "Syntax-checks the WebUI JavaScript with `node --check` when node is available."
        val jsDir = rootProject.projectDir.resolve("module/webroot/js")
        inputs.dir(jsDir)
        doLast {
            val nodeOk =
                try {
                    ProcessBuilder("node", "--version").redirectErrorStream(true).start().waitFor() == 0
                } catch (e: Exception) {
                    false
                }
            if (!nodeOk) {
                logger.lifecycle("checkWebrootJs: node not found; skipping the WebUI JS syntax check")
                return@doLast
            }
            // The WebUI files are ES modules. `node --check <file>` mis-detects them and silently
            // passes real syntax errors, so feed each file on stdin with an explicit module type —
            // that form exits non-zero (with a "[stdin]:LINE" location) on a genuine error.
            val failures = mutableListOf<String>()
            jsDir.walk().filter { it.isFile && it.extension == "js" }.forEach { f ->
                val p = ProcessBuilder("node", "--input-type=module", "--check")
                    .redirectInput(f)
                    .redirectErrorStream(true)
                    .start()
                val msg = p.inputStream.bufferedReader().readText().trim()
                if (p.waitFor() != 0) {
                    val where = msg.lines().firstOrNull()?.replace("[stdin]", f.name) ?: "syntax error"
                    failures.add("  ${f.relativeTo(rootProject.projectDir)}: $where")
                }
            }
            if (failures.isNotEmpty()) {
                throw GradleException("WebUI JavaScript syntax errors:\n" + failures.joinToString("\n"))
            }
            logger.lifecycle("checkWebrootJs: all WebUI JS files parse OK")
        }
    }

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalized = variant.name.replaceFirstChar { it.uppercase() }
        val isDebug = variant.buildType == "debug"

        // Stage per variant so debug and release never clobber each other.
        val tempModuleDir = layout.buildDirectory.dir("module/${variant.name}")
        val zipFileName = "TEESimulator-$verName-$gitCommitCount-$gitCommitHash-$capitalized.zip"

        // Where AGP leaves this variant's native build: stripped .so under
        // stripped_native_libs, and the injector executable (never stripped or
        // packaged by AGP) only under intermediates/cmake.
        val strippedLibs =
            layout.buildDirectory.dir(
                "intermediates/stripped_native_libs/${variant.name}/strip${capitalized}DebugSymbols/out/lib"
            )
        val cmakeObj = layout.buildDirectory.dir("intermediates/cmake/${variant.name}/obj")

        // Stage every module file. Sync clears stale files from previous runs.
        val prepareModuleFilesTask =
            tasks.register<Sync>("prepareModuleFiles${capitalized}") {
                group = "TEESimulator Module Packaging"
                description = "Prepares all files for the ${variant.name} module zip."

                // Reject a WebUI JS syntax error before it ships (no-op when node is absent).
                dependsOn(checkWebrootJs)

                if (isDebug) {
                    dependsOn("package${capitalized}")
                } else {
                    dependsOn("minify${capitalized}WithR8")
                }
                // Stripped .so land in stripped_native_libs; the injector executable
                // is only collected under intermediates/cmake by externalNativeBuild.
                dependsOn("strip${capitalized}DebugSymbols")
                dependsOn("externalNativeBuild${capitalized}")

                if (isDebug) {
                    // Debug has no R8 pass; ship the packaged APK. module/daemon falls
                    // back to service.apk when classes.dex is absent.
                    from(variant.artifacts.get(SingleArtifact.APK)) {
                        include("*.apk")
                        rename { "service.apk" }
                    }
                } else {
                    // The control daemon's dex; app_process runs it at boot.
                    from(
                        layout.buildDirectory.dir(
                            "intermediates/dex/${variant.name}/minify${capitalized}WithR8"
                        )
                    ) {
                        include("classes.dex")
                    }
                }

                // The stripped interceptor libraries, keeping their <abi>/ layout; the
                // runtime stubs (libcrypto/libbinder/libutils) stay out of the zip.
                from(strippedLibs) {
                    include("**/libteesim_keymint.so", "**/libteesim_keystore.so")
                }

                // The injector executable and the WebUI's admin-socket client, one per <abi>/.
                from(cmakeObj) { include("**/inject", "**/teesim-uds") }

                // The module scripts and WebUI (service.sh, daemon, customize.sh,
                // sepolicy.rule, config.default.json, webroot/); module.prop is
                // templated separately below.
                val sourceModuleDir = rootProject.projectDir.resolve("module")
                from(sourceModuleDir) { exclude("module.prop") }

                // module.prop with git-derived version fields filled in.
                from(sourceModuleDir) {
                    include("module.prop")
                    expand(
                        "REPLACEMEVERCODE" to gitCommitCount.toString(),
                        "REPLACEMEVER" to
                            "$verName ($gitCommitCount-$gitCommitHash-${variant.name})",
                    )
                }

                into(tempModuleDir)
            }

        // Zip the staged module into out/.
        val zipTask =
            tasks.register<Zip>("zip${capitalized}") {
                group = "TEESimulator Module Packaging"
                description = "Creates the flashable ${variant.name} module zip in out/."
                dependsOn(prepareModuleFilesTask)
                archiveFileName.set(zipFileName)
                destinationDirectory.set(rootProject.rootDir.resolve("out"))
                from(tempModuleDir)
            }

        // Per-root-manager install tasks: push the zip and let the manager flash it.
        fun createInstallTasks(rootProvider: String, installCli: String) {
            val pushTask =
                tasks.register<Exec>("push${rootProvider}Module${capitalized}") {
                    group = "TEESimulator Module Installation"
                    description =
                        "Pushes the ${variant.name} module zip to the device for $rootProvider."
                    dependsOn(zipTask)
                    commandLine(
                        adb(
                            "push",
                            zipTask.get().archiveFile.get().asFile.absolutePath,
                            "/data/local/tmp",
                        )
                    )
                }

            val installTask =
                tasks.register<Exec>("install${rootProvider}${capitalized}") {
                    group = "TEESimulator Module Installation"
                    description = "Installs the ${variant.name} module via $rootProvider."
                    dependsOn(pushTask)
                    commandLine(adb("shell", "su", "-c", "$installCli /data/local/tmp/$zipFileName"))
                }

            tasks.register<Exec>("install${rootProvider}AndReboot${capitalized}") {
                group = "TEESimulator Module Installation"
                description = "Installs the ${variant.name} module via $rootProvider and reboots."
                dependsOn(installTask)
                commandLine(adb("reboot"))
            }
        }

        createInstallTasks("Magisk", "magisk --install-module")
        createInstallTasks("Ksu", "ksud module install")
        createInstallTasks("Apatch", "/data/adb/apd module install")
    }
}
