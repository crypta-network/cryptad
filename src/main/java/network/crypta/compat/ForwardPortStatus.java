package network.crypta.compat;

/** Compatibility status for a forwarded port check. */
public record ForwardPortStatus(int status, String reasonString, int externalPort) {
  public static final int DEFINITE_SUCCESS = 1;
  public static final int PROBABLE_SUCCESS = 2;
  public static final int MAYBE_SUCCESS = 3;
  public static final int PROBABLE_FAILURE = 4;
  public static final int DEFINITE_FAILURE = 5;
}
