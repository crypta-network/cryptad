package network.crypta.support;

/**
 * * Unified class for getting java properties to control unit test behaviour. * * @author infinity0
 */
final public class TestProperty {

    final public static boolean BENCHMARK = Boolean.getBoolean("test.benchmark");
    final public static boolean VERBOSE = Boolean.getBoolean("test.verbose");
    final public static boolean EXTENSIVE = Boolean.getBoolean("test.extensive");
    final public static String L10nPath_test =
            System.getProperty("test.l10npath_test", "test/network/crypta/l10n/");
    final public static String L10nPath_main =
            System.getProperty("test.l10npath_main", "src/network/crypta/l10n/");

    private TestProperty() {
    }

}
