plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
}

version = rootProject.version

dependencies {
  implementation(project(":foundation-config"))
  implementation(project(":foundation-support"))
  implementation(project(":foundation-crypto-keys"))
  implementation(libs.bcprov)
  implementation(libs.bcpkix)
  implementation(libs.slf4jApi)
}
