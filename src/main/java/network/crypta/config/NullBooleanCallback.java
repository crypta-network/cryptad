package network.crypta.config;

import network.crypta.support.api.BooleanCallback;

public class NullBooleanCallback extends BooleanCallback {

  @Override
  public Boolean get() {
    return false;
  }

  @Override
  public void set(Boolean val) throws InvalidConfigValueException {
    // Ignore
  }
}
