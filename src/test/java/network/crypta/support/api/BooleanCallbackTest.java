package network.crypta.support.api;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

class BooleanCallbackTest {

  @Test
  void canCreateBooleanCallbackFromLambdas()
      throws NodeNeedRestartException, InvalidConfigValueException {
    BooleanCallback callback = BooleanCallback.from(() -> true, (value) -> theValue = value);
    callback.set(true);

    assertThat(theValue, Matchers.is(true));
  }

  @Test
  void canThrowInvalidConfigValueException()
      throws NodeNeedRestartException, InvalidConfigValueException {
    BooleanCallback callback =
        BooleanCallback.from(
            () -> true,
            (value) -> {
              throw new InvalidConfigValueException("invalid");
            });
    assertThrows(InvalidConfigValueException.class, () -> callback.set(true));
  }

  @Test
  void canThrowNodeNeedRestartException()
      throws NodeNeedRestartException, InvalidConfigValueException {
    BooleanCallback callback =
        BooleanCallback.from(
            () -> true,
            (value) -> {
              throw new NodeNeedRestartException("needs restart");
            });
    assertThrows(NodeNeedRestartException.class, () -> callback.set(true));
  }

  @Test
  void getGivesTheSetVariable() throws NodeNeedRestartException, InvalidConfigValueException {
    BooleanCallback callback =
        BooleanCallback.from(
            () -> theValue,
            (value -> {
              theValue = value;
            }));
    callback.set(true);
    boolean trueValue = callback.get();
    callback.set(false);
    boolean falseValue = callback.get();
    assertThat(trueValue, Matchers.is(true));
    assertThat(falseValue, Matchers.is(false));
  }

  private boolean theValue = false;
}
