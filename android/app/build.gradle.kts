plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.kapt")
}

android {
    namespace = "com.ghostdeveloper.spdecode"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.ghostdeveloper.spdecode"
        minSdk = 24
        targetSdk = 35
        versionCode = 17
        versionName = "1.0.6"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        resourceConfigurations += listOf("en", "es", "pt-rBR", "ar")
    }
    buildFeatures { compose = true }
    packaging {
        resources {
            // Bouncy Castle and jspecify both ship JVM 9 multi-release metadata;
            // Android does not execute those JVM-specific OSGi descriptors.
            excludes += "META-INF/versions/**"
        }
    }
    // Production keystore passwords are injected only at build time by CI.
    // Never commit keystores, signing secrets or their obfuscated equivalents.
    signingConfigs {
        val path=providers.environmentVariable("SPDECODE_RELEASE_STORE_FILE").orNull
        val storePass=providers.environmentVariable("SPDECODE_RELEASE_STORE_PASSWORD").orNull
        val alias=providers.environmentVariable("SPDECODE_RELEASE_KEY_ALIAS").orNull
        val keyPass=providers.environmentVariable("SPDECODE_RELEASE_KEY_PASSWORD").orNull
        if(!path.isNullOrBlank() && !storePass.isNullOrBlank() &&
            !alias.isNullOrBlank() && !keyPass.isNullOrBlank()) {
            create("production") {
                storeFile=file(path)
                storePassword=storePass
                keyAlias=alias
                keyPassword=keyPass
                enableV1Signing=true
                enableV2Signing=true
                enableV3Signing=true
            }
        }
    }
    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig=signingConfigs.findByName("production")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { animationsDisabled = true }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.04.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.10.1")
    implementation("com.google.code.gson:gson:2.13.1")
    // Lightweight Argon2id + XChaCha20-Poly1305 primitives for standard .ehi.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.0")
    implementation("androidx.datastore:datastore-preferences:1.1.7")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("androidx.room:room-runtime:2.7.2")
    implementation("androidx.room:room-ktx:2.7.2")
    kapt("androidx.room:room-compiler:2.7.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
