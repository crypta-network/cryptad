plugins {
  // Apply SonarQube/SonarCloud plugin centrally via convention plugin
  id("org.sonarqube")
}

// Central Sonar configuration for all projects applying this convention
sonar {
  properties {
    property("sonar.projectKey", "crypta-network_cryptad")
    property("sonar.organization", "crypta-network")
  }
}
