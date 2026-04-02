plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-support"))
  implementation(project(":foundation-store"))
  implementation(project(":foundation-store-contracts"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":kernel-content"))
  implementation(project(":runtime-spi"))
  implementation(project(":thirdparty-onion"))
  implementation(project(":thirdparty-legacy"))

  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(libs.commonsLang3)
  implementation(libs.picocli)
  implementation(libs.slf4jApi)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.jetbrainsAnnotations)
  compileOnly(libs.logbackClassic)
}

dependencies {
  implementation(project(":foundation-support"))
  implementation(project(":foundation-store"))
  implementation(project(":foundation-store-contracts"))
  implementation(project(":foundation-crypto-keys"))
  implementation(project(":interop-wire"))
  implementation(project(":foundation-config"))
  implementation(project(":foundation-fs"))
  implementation(project(":foundation-compat"))
  implementation(project(":kernel-content"))
  implementation(project(":runtime-spi"))
  implementation(project(":thirdparty-onion"))
  implementation(project(":thirdparty-legacy"))
  implementation(libs.slf4jApi)
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.jna)
  implementation(libs.jnaPlatform)
  implementation(libs.commonsCompress)
  implementation(libs.commonsLang3)
  implementation(libs.picocli)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.logbackClassic)
  compileOnly(libs.jetbrainsAnnotations)
}
