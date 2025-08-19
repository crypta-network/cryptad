package network.crypta.support;

/**
 * * Unified class for getting java properties to control unit test behaviour. * * @author infinity0
 */
public final class TestProperty {

  public static final boolean BENCHMARK = Boolean.getBoolean("test.benchmark");
  public static final boolean VERBOSE = Boolean.getBoolean("test.verbose");
  public static final boolean EXTENSIVE = Boolean.getBoolean("test.extensive");
  public static final String L10nPath_test =
      System.getProperty("test.l10npath_test", "test/network/crypta/l10n/");
  public static final String L10nPath_main =
      System.getProperty("test.l10npath_main", "src/network/crypta/l10n/");

  private TestProperty() {}
}
