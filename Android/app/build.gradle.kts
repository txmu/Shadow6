plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

val nativeProfileCatalog = layout.buildDirectory.file("generated/native-profile-assets/native-profiles.json")
val generateNativeProfileCatalog by tasks.registering(Exec::class) {
    val repositoryRoot = projectDir.parentFile.parentFile
    inputs.file(repositoryRoot.resolve("Crosed/native_profiles.py"))
    inputs.file(repositoryRoot.resolve("Android/export_native_profiles.py"))
    outputs.file(nativeProfileCatalog)
    commandLine("python3", repositoryRoot.resolve("Android/export_native_profiles.py").absolutePath,
        "--output", nativeProfileCatalog.get().asFile.absolutePath)
}

fun enabled(name: String, default: Boolean = true) = providers.gradleProperty(name).orNull?.toBooleanStrictOrNull() ?: default

android {
    namespace = "org.shadow6.android"
    sourceSets.getByName("main").assets.srcDir(nativeProfileCatalog.get().asFile.parentFile)
    compileSdk = 36
    defaultConfig {
        applicationId = "org.shadow6.android"
        minSdk = 28
        targetSdk = 36
        versionCode = 4
        versionName = "1.2.0"
        buildConfigField("boolean", "INCLUDE_GO_CORE", enabled("shadow6.includeGoCore").toString())
        buildConfigField("boolean", "INCLUDE_RUST_CORE", enabled("shadow6.includeRustCore").toString())
        buildConfigField("boolean", "INCLUDE_D_CORE", enabled("shadow6.includeDCore", true).toString())
        buildConfigField("boolean", "INCLUDE_NIM_CORE", enabled("shadow6.includeNimCore", true).toString())
        buildConfigField("boolean", "INCLUDE_GATE", enabled("shadow6.includeGate").toString())
        buildConfigField("boolean", "INCLUDE_CHAT", enabled("shadow6.includeChat").toString())
        buildConfigField("boolean", "INCLUDE_GAMES", enabled("shadow6.includeGames").toString())
        buildConfigField("boolean", "INCLUDE_PACKAGES", enabled("shadow6.includePackages").toString())
        buildConfigField("boolean", "INCLUDE_AI", enabled("shadow6.includeAI").toString())
    }
    buildFeatures { compose = true; buildConfig = true }
    packaging {
        jniLibs.useLegacyPackaging = true
        // Also exclude artifacts left by older incremental native builds.
        jniLibs.excludes += "**/libshadow6_zig.so"
    }
    androidResources {
        localeFilters += listOf("en", "zh-rCN")
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}

tasks.named("preBuild").configure { dependsOn(generateNativeProfileCatalog) }

dependencies {
    // Compose 1.12 requires compileSdk 37.  Keep the dependency train aligned
    // with this project's pinned API 36 toolchain.
    val composeBom = platform("androidx.compose:compose-bom:2025.12.01")
    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.activity:activity-compose:1.12.4")
    implementation("androidx.compose.material3:material3")
    // Use the small core icon artifact explicitly.  Avoid material-icons-
    // extended: its generated 80+ MiB jar materially increases Kotlin compiler
    // memory for the handful of icons used by this app.
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.ui:ui")
    testImplementation("junit:junit:4.13.2")
    // JVM contract tests serialize real JSON; android.jar methods are stubs.
    testImplementation("org.json:json:20240303")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
