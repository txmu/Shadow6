plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

fun enabled(name: String, default: Boolean = true) = providers.gradleProperty(name).orNull?.toBooleanStrictOrNull() ?: default

android {
    namespace = "org.shadow6.android"
    compileSdk = 36
    defaultConfig {
        applicationId = "org.shadow6.android"
        minSdk = 28
        targetSdk = 36
        versionCode = 4
        versionName = "1.2.0"
        buildConfigField("boolean", "INCLUDE_GO_CORE", enabled("shadow6.includeGoCore").toString())
        buildConfigField("boolean", "INCLUDE_RUST_CORE", enabled("shadow6.includeRustCore").toString())
        buildConfigField("boolean", "INCLUDE_ZIG_CORE", enabled("shadow6.includeZigCore").toString())
        buildConfigField("boolean", "INCLUDE_GATE", enabled("shadow6.includeGate").toString())
        buildConfigField("boolean", "INCLUDE_CHAT", enabled("shadow6.includeChat").toString())
        buildConfigField("boolean", "INCLUDE_GAMES", enabled("shadow6.includeGames").toString())
        buildConfigField("boolean", "INCLUDE_PACKAGES", enabled("shadow6.includePackages").toString())
        buildConfigField("boolean", "INCLUDE_AI", enabled("shadow6.includeAI").toString())
    }
    buildFeatures { compose = true; buildConfig = true }
    packaging { jniLibs.useLegacyPackaging = true }
    androidResources {
        localeFilters += listOf("en", "zh-rCN")
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
}

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
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
