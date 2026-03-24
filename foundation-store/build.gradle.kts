plugins {
  id("cryptad.java-kotlin-conventions")
  id("cryptad.spotless")
  `java-library`
}

version = rootProject.version

dependencies {
  api(project(":foundation-support"))
  api(project(":foundation-store-contracts"))
  api(project(":foundation-crypto-keys"))

  implementation(project(":thirdparty-onion"))
  implementation(libs.slf4jApi)
  implementation(files(rootProject.file("libs/wrapper.jar")))

  compileOnly(libs.jetbrainsAnnotations)
}
