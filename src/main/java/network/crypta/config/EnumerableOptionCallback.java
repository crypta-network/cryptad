package network.crypta.config;

public interface EnumerableOptionCallback {
  String[] getPossibleValues();

  /** Return the current value */
  String get();
}
