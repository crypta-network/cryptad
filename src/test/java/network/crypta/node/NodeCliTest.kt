package network.crypta.node

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import picocli.CommandLine

class NodeCliTest {

  @Test
  fun serviceMode_valid_service() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "service")
    assertEquals(cli.serviceModeOverride(), "service")
  }

  @Test
  fun serviceMode_valid_user() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "user")
    assertEquals(cli.serviceModeOverride(), "user")
  }

  @Test
  fun serviceMode_invalid_value_throws() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "foo")
    assertThrows<CommandLine.ParameterException> {
      // Validation happens when computing the override
      cli.serviceModeOverride()
    }
  }

  @Test
  fun serviceMode_case_insensitive() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "SeRvIcE")
    assertEquals(cli.serviceModeOverride(), "service")
  }

  @Test
  fun shortcuts_service_sets_mode() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service")
    assertEquals(cli.serviceModeOverride(), "service")
  }

  @Test
  fun shortcuts_user_sets_mode() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--user")
    assertEquals(cli.serviceModeOverride(), "user")
  }

  @Test
  fun shortcuts_mutually_exclusive() {
    val cli = NodeCli()
    // Parsing should fail because the ArgGroup is exclusive
    assertThrows<CommandLine.MutuallyExclusiveArgsException> {
      CommandLine(cli).parseArgs("--service", "--user")
    }
  }

  @Test
  fun config_file_positional_only() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("/etc/cryptad/cryptad.ini")
    assertEquals(cli.explicitConfigFile(), java.io.File("/etc/cryptad/cryptad.ini"))
  }

  @Test
  fun config_file_flag_overrides_positional() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("-c", "/opt/cryptad/cryptad.ini", "/etc/cryptad/cryptad.ini")
    assertEquals(cli.explicitConfigFile(), java.io.File("/opt/cryptad/cryptad.ini"))
  }

  @Test
  fun directory_overrides_collected() {
    val cli = NodeCli()
    CommandLine(cli)
      .parseArgs(
        "--config-dir",
        "/cfg",
        "--data-dir",
        "/data",
        "--cache-dir",
        "/cache",
        "--run-dir",
        "/run",
      )
    val m = cli.directoryOverrides()
    assertEquals("/cfg", m["configDir"])
    assertEquals("/data", m["dataDir"])
    assertEquals("/cache", m["cacheDir"])
    assertEquals("/run", m["runDir"])
  }

  @Test
  fun logsDir_override_collected() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--logs-dir", "/var/log/cryptad")
    val m = cli.directoryOverrides()
    assertEquals("/var/log/cryptad", m["logsDir"])
  }

  @Test
  fun logsDir_absent_not_in_map() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs()
    val m = cli.directoryOverrides()
    // Should not contain logsDir when not provided
    assertEquals(null, m["logsDir"], "service")
  }
}
