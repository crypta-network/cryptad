package network.crypta.config;

import network.crypta.support.api.IntCallback;

public class NullIntCallback extends IntCallback {

  @Override
  public Integer get() {
    return 0;
  }

  @Override
  public void set(Integer val) throws InvalidConfigValueException {
    // Ignore
  }
}
