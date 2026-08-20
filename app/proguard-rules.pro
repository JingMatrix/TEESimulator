# The entry point app_process invokes.
-keepclasseswithmembers class org.matrix.teesim.App {
    public static void main(java.lang.String[]);
}

# Native (JNI) methods are resolved by their Java_<class>_<method> symbol names. The daemon
# System.load()s libteesim_logcat.so and calls LogTail's native methods, whose exported names are
# hard-coded in logcat/exports.map -- so R8 must not rename the declaring class or those methods, or
# ART looks up Java_<obfuscated> and the daemon dies with UnsatisfiedLinkError on the log-reader
# thread (the PR #266 release-only crash loop). This is the stock android rule, absent here because
# the release build lists only this custom file (no getDefaultProguardFile).
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# BouncyCastle providers are loaded by name/reflection; keep them intact.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

# We reference hidden framework classes that are provided at runtime only.
-dontwarn android.**
