package network.crypta.runtime.bootstrap;

import java.io.File;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class NodeCliTest {
  @Test
  void classIsLoadable() {
    assertNotNull(NodeCli.class);
  }

  @Test
  void explicitConfigFile_whenNoArgs_expectNull() {
    NodeCli cli = new NodeCli();

    new CommandLine(cli).parseArgs();

    assertNull(cli.explicitConfigFile());
  }

  @Test
  void explicitConfigFile_whenConfigFileOptionProvided_expectOptionValue() {
    NodeCli cli = new NodeCli();
    File expected = new File("/etc/cryptad/cryptad.ini");

    new CommandLine(cli).parseArgs("-c", expected.getPath());

    assertEquals(expected, cli.explicitConfigFile());
  }

  @Test
  void explicitConfigFile_whenPositionalProvided_expectPositionalValue() {
    NodeCli cli = new NodeCli();
    File expected = new File("/opt/cryptad/cryptad.ini");

    new CommandLine(cli).parseArgs(expected.getPath());

    assertEquals(expected, cli.explicitConfigFile());
  }

  @Test
  void explicitConfigFile_whenOptionAndPositionalProvided_expectOptionWins() {
    NodeCli cli = new NodeCli();
    File optionFile = new File("/etc/cryptad/cryptad.ini");
    File positionalFile = new File("/tmp/cryptad.ini");

    new CommandLine(cli).parseArgs("--config-file", optionFile.getPath(), positionalFile.getPath());

    assertEquals(optionFile, cli.explicitConfigFile());
  }
}
