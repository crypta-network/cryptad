package network.crypta.config;

public interface ConfigConsumer<T> {
  void accept(T value) throws InvalidConfigValueException, NodeNeedRestartException;
}
