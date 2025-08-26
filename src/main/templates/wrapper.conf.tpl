# Cryptad Wrapper configuration (generated from template)

# Classpath: load all jars from ../lib relative to this conf file
wrapper.java.classpath.1=lib/*

# JVM arguments
wrapper.java.additional.1=-Dnetworkaddress.cache.ttl=0
wrapper.java.additional.2=-Dnetworkaddress.cache.negative.ttl=0
wrapper.java.additional.3=-Djava.net.preferIPv4Stack=false
wrapper.java.additional.4=--enable-native-access=ALL-UNNAMED
wrapper.java.additional.5=--add-opens=java.base/java.lang=ALL-UNNAMED
wrapper.java.additional.6=--add-opens=java.base/java.util=ALL-UNNAMED
wrapper.java.additional.7=--add-opens=java.base/java.io=ALL-UNNAMED
wrapper.java.additional.8=-enableassertions:freenet

# Main class
wrapper.java.mainclass=network.crypta.node.NodeStarter

# Console and log
wrapper.console.format=PM
wrapper.console.loglevel=INFO
wrapper.logfile=
wrapper.logfile.format=LPTM
wrapper.logfile.loglevel=INFO
wrapper.logfile.maxsize=2M
wrapper.logfile.maxfiles=3
wrapper.syslog.loglevel=NONE

# Memory sizing
wrapper.java.initmemory=64
wrapper.java.maxmemory=1536

# Java command and working dir
wrapper.java.command=java
wrapper.working.dir=..

# Wrapper jar location (relative to distribution root)
wrapper.jarfile=lib/wrapper.jar
wrapper.java.library.path.1=lib

# Lifecycle
wrapper.restart.reload_configuration=TRUE
wrapper.anchor.poll_interval=1

# Backend type
wrapper.backend.type=PIPE
