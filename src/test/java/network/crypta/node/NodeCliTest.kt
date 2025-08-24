package network.crypta.node

import org.junit.Assert.assertEquals
import org.junit.Test
import picocli.CommandLine

class NodeCliTest {

  @Test
  fun serviceMode_valid_service() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "service")
    assertEquals("service", cli.serviceModeOverride())
  }

  @Test
  fun serviceMode_valid_user() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "user")
    assertEquals("user", cli.serviceModeOverride())
  }

  @Test(expected = CommandLine.ParameterException::class)
  fun serviceMode_invalid_value_throws() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "foo")
    // Validation happens when computing the override
    cli.serviceModeOverride()
  }

  @Test
  fun serviceMode_case_insensitive() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service-mode", "SeRvIcE")
    assertEquals("service", cli.serviceModeOverride())
  }

  @Test
  fun shortcuts_service_sets_mode() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--service")
    assertEquals("service", cli.serviceModeOverride())
  }

  @Test
  fun shortcuts_user_sets_mode() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("--user")
    assertEquals("user", cli.serviceModeOverride())
  }

  @Test(expected = CommandLine.MutuallyExclusiveArgsException::class)
  fun shortcuts_mutually_exclusive() {
    val cli = NodeCli()
    // Parsing should fail because the ArgGroup is exclusive
    CommandLine(cli).parseArgs("--service", "--user")
  }

  @Test
  fun config_file_positional_only() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("/etc/cryptad/cryptad.ini")
    assertEquals(java.io.File("/etc/cryptad/cryptad.ini"), cli.explicitConfigFile())
  }

  @Test
  fun config_file_flag_overrides_positional() {
    val cli = NodeCli()
    CommandLine(cli).parseArgs("-c", "/opt/cryptad/cryptad.ini", "/etc/cryptad/cryptad.ini")
    assertEquals(java.io.File("/opt/cryptad/cryptad.ini"), cli.explicitConfigFile())
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
}
