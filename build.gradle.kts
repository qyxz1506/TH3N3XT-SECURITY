plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}
android {
    namespace = "com.th3next.security"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.th3next.security"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
    }
}
dependencies {
    implementation("androidx.documentfile:documentfile:1.0.1")
}
