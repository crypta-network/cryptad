package network.crypta.node;

/**
 * Builder for {@link RequestClient} instances.
 *
 * <p>This builder creates lightweight, immutable {@code RequestClient} snapshots that the scheduler
 * can query for client-level attributes. Unless configured otherwise, the produced clients are
 * non-persistent and do not use the real-time flag. The builder itself is mutable and reusable; it
 * is not thread-safe.
 *
 * <p>Defaults
 *
 * <ul>
 *   <li>{@link #persistent()} → {@code false}
 *   <li>{@link #realTime()} → {@code false}
 * </ul>
 *
 * <p>Usage example:
 *
 * <pre>{@code
 * RequestClient bulk = new RequestClientBuilder().build();
 * RequestClient rt   = new RequestClientBuilder().realTime().build();
 * }</pre>
 *
 * @author <a href="mailto:bombe@freenetproject.org">David ‘Bombe’ Roden</a>
 */
public class RequestClientBuilder {

  private boolean persistent;
  private boolean realTime;

  /**
   * Creates a builder with non-persistent, non-real-time defaults.
   *
   * <p>Callers may mutate the builder fluently and then call {@link #build()} to capture an
   * immutable request-client snapshot.
   */
  public RequestClientBuilder() {}

  /**
   * Enables persistence for subsequently {@link #build() built} clients.
   *
   * <p>This method sets the internal flag to {@code true}. It returns the same builder instance to
   * allow fluent chaining.
   *
   * @return this builder (never {@code null})
   */
  public RequestClientBuilder persistent() {
    persistent = true;
    return this;
  }

  /**
   * Sets the persistence flag for subsequently {@link #build() built} clients.
   *
   * <p>The most recent value provided wins. Calling {@code persistent(true).persistent(false)} will
   * yield clients that report {@code false}.
   *
   * @param persistent {@code true} to mark clients as persistent; {@code false} otherwise
   * @return this builder (never {@code null})
   */
  public RequestClientBuilder persistent(boolean persistent) {
    this.persistent = persistent;
    return this;
  }

  /**
   * Enables the real-time scheduling flag for subsequently {@link #build() built} clients.
   *
   * <p>This method sets the internal flag to {@code true}. It returns the same builder instance to
   * allow fluent chaining.
   *
   * @return this builder (never {@code null})
   */
  public RequestClientBuilder realTime() {
    realTime = true;
    return this;
  }

  /**
   * Sets the real-time scheduling flag for subsequently {@link #build() built} clients.
   *
   * <p>The most recent value provided wins.
   *
   * @param realTime {@code true} to enable real-time handling; {@code false} for normal handling
   * @return this builder (never {@code null})
   */
  public RequestClientBuilder realTime(boolean realTime) {
    this.realTime = realTime;
    return this;
  }

  /**
   * Builds a {@link RequestClient} snapshot.
   *
   * <p>The returned instance captures the builder state at call time. Subsequent mutations of this
   * builder do not affect previously built clients. The resulting {@code RequestClient} is
   * immutable and thread-safe to query.
   *
   * @return a new {@code RequestClient} reflecting the current builder settings
   */
  public RequestClient build() {
    return new RequestClient() {
      // Capture a snapshot of the current builder state so later changes to the builder do not
      // affect this instance.
      private final boolean persistent = RequestClientBuilder.this.persistent;
      private final boolean realTime = RequestClientBuilder.this.realTime;

      @Override
      public boolean persistent() {
        // Stable for the lifetime of this instance.
        return persistent;
      }

      @Override
      public boolean realTimeFlag() {
        // Stable for the lifetime of this instance.
        return realTime;
      }
    };
  }
}
