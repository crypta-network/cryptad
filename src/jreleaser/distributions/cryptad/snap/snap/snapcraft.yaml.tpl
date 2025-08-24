# {{jreleaserCreationStamp}}
name: {{snapPackageName}}
version: "{{projectVersion}}"
summary: {{projectDescription}}
description: {{projectLongDescription}}

grade: {{snapGrade}}
confinement: {{snapConfinement}}
base: {{snapBase}}
type: app

apps:
  {{distributionExecutableName}}:
    command: bin/{{distributionExecutableUnix}}
    environment:
      # Use OpenJDK 21 from stage-packages; path varies by arch
      JAVA_HOME: "$SNAP/usr/lib/jvm/java-21-openjdk-$SNAP_ARCH"
      PATH: "$SNAP/bin:$PATH:$JAVA_HOME/bin"
    {{#snapHasLocalPlugs}}
    plugs:
      {{#snapLocalPlugs}}
      - {{.}}
      {{/snapLocalPlugs}}
    {{/snapHasLocalPlugs}}

parts:
  {{distributionExecutableName}}:
    plugin: dump
    source: {{distributionUrl}}
    source-checksum: sha256/{{distributionChecksumSha256}}
    override-build: |
      set -e
      craftctl default
      # Ensure launcher is world-readable & executable for snap validation
      if [ -f "$CRAFT_PART_INSTALL/bin/{{distributionExecutableUnix}}" ]; then
        chmod 0755 "$CRAFT_PART_INSTALL/bin/{{distributionExecutableUnix}}"
      fi
    stage-packages:
      - curl
      - openjdk-21-jre-headless
      - ca-certificates
      - ca-certificates-java
