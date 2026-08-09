# The entry point app_process invokes.
-keepclasseswithmembers class org.matrix.teesim.App {
    public static void main(java.lang.String[]);
}

# BouncyCastle providers are loaded by name/reflection; keep them intact.
-keep class org.bouncycastle.jcajce.provider.** { *; }
-keep class org.bouncycastle.jce.provider.** { *; }
-dontwarn javax.naming.**

# We reference hidden framework classes that are provided at runtime only.
-dontwarn android.**
