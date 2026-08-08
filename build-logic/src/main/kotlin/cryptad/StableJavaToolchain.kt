package cryptad

import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainSpec
import org.gradle.jvm.toolchain.JvmVendorSpec

/** Selects the Java distribution used for Stable release builds and installed-tree evidence. */
internal fun JavaToolchainSpec.selectStableJava25() {
  languageVersion.set(JavaLanguageVersion.of(25))
  vendor.set(JvmVendorSpec.ADOPTIUM)
}
