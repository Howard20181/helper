# Keep all classes in the helper package
# This is necessary because the library uses reflection extensively
-keep class io.github.libxposed.helper.** { *; }

# Keep all attributes needed for reflection
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod
-keepattributes *Annotation*
-keepattributes SourceFile
-keepattributes LineNumberTable
-keepattributes Exceptions

# Don't warn about missing classes from dependencies
-dontwarn androidx.annotation.**
-dontwarn io.github.libxposed.api.**
-dontwarn dalvik.system.**

# Keep parameter names for better debugging and reflection
-keepparameternames

# Don't obfuscate - this is critical for a library that uses reflection
-dontobfuscate

# Optional: repackage to reduce size while keeping names
# -repackageclasses "libxposed.helper"
