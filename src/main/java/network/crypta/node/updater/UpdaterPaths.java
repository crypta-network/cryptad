package network.crypta.node.updater;

/** Common HTTP paths used by the core updater UI/endpoints. */
public final class UpdaterPaths {
  private static final char URL_PATH_SEPARATOR = '/';
  private static final String URL_PATH_SEPARATOR_STR = String.valueOf(URL_PATH_SEPARATOR);
  private static final String CORE_UPDATE_SEGMENT = "core-update";
  public static final String CORE_UPDATE_PATH =
      URL_PATH_SEPARATOR_STR + CORE_UPDATE_SEGMENT + URL_PATH_SEPARATOR_STR;

  private UpdaterPaths() {}
}
