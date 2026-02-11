package com.onionnetworks.fec;

/**
 * Factory for constructing forward error correction (FEC) codecs.
 *
 * <p>This abstract base coordinates creation of {@link FECCode} instances without binding callers
 * to a specific implementation. A JVM-wide default factory can be configured via the system
 * property {@code com.onionnetworks.fec.defaultcodefactoryclass}; when absent the bundled {@link
 * DefaultFECCodeFactory} is used. Typical consumers get the factory once, cache it, and create
 * codes as blocks are scheduled for encoding or repair.
 *
 * <p>Instances are expected to be stateless or thread-safe; the default supplier is lazily
 * initialized in a synchronized accessor so repeated lookups are safe across threads. Concrete
 * factories may impose additional constraints on supported {@code k} and {@code n} values or use
 * native acceleration, but they all honor the {@link FECCode} contract.
 *
 * <ul>
 *   <li>Locates the active FEC implementation based on runtime configuration.
 *   <li>Provides a single entry point for allocating encoder/decoder state.
 *   <li>Encapsulates fallback behavior when custom providers fail to load.
 * </ul>
 *
 * @see FECCode
 * @see DefaultFECCodeFactory
 * @author Justin F. Chapweske (justin@chapweske.com)
 */
public abstract class FECCodeFactory {

  /**
   * Shared cached instance of the default factory selected for this JVM.
   *
   * <p>Lazily populated when {@link #getDefault()} is first called and reused thereafter; callers
   * should treat it as internal, read-mostly global state.
   */
  private static FECCodeFactory def;

  /**
   * Protected constructor for subclass implementations.
   *
   * <p>Provider implementations typically expose a public no-argument constructor so {@link
   * #getDefault()} can instantiate them reflectively. The base type performs no initialization
   * beyond standard object construction, leaving concrete factories to precompute lookup tables or
   * validate configuration in their {@link #createFECCode(int, int)} implementations. Keeping this
   * constructor lightweight avoids unnecessary overhead when the factory is cached globally yet
   * accessed concurrently across threads.
   */
  protected FECCodeFactory() {}

  /**
   * Create a forward error correction code parameterized by the requested packet counts.
   *
   * <p>Implementations construct an {@link FECCode} configured for the supplied values without
   * caching the resulting instance. Callers typically invoke this for each distinct block size to
   * allocate encoder/decoder state that matches the number of source packets ({@code k}) and total
   * packets ({@code n}). Most providers expect {@code n} to be greater than or equal to {@code k};
   * unsupported combinations may trigger provider-specific validation failures.
   *
   * @param k The number of original source packets the code will protect; must be positive.
   * @param n Total packet count (source plus repair) to generate; typically at least k.
   * @return Mutable {@link FECCode} instance ready to encode or decode the specified block size.
   */
  public abstract FECCode createFECCode(int k, int n);

  /**
   * Return the lazily initialized default factory configured for this JVM.
   *
   * <p>The method consults the {@code com.onionnetworks.fec.defaultcodefactoryclass} system
   * property and attempts to load the named class via reflection; if loading or instantiation
   * fails, it falls back to {@link DefaultFECCodeFactory}. Synchronization ensures that the lookup
   * and caching happen once, even under concurrent calls, and the same instance is returned for all
   * following requests.
   *
   * <pre>{@code
   * FECCodeFactory factory = FECCodeFactory.getDefault();
   * FECCode code = factory.createFECCode(32, 256);
   * }</pre>
   *
   * @return Shared factory instance selected from configuration or the built-in fallback provider.
   */
  public static synchronized FECCodeFactory getDefault() {
    if (def == null) {
      try {
        String factoryClass =
            System.getProperty(
                "com.onionnetworks.fec.defaultcodefactoryclass",
                "com.onionnetworks.fec.DefaultFECCodeFactory");
        Class<?> clazz = Class.forName(factoryClass);
        def = clazz.asSubclass(FECCodeFactory.class).getDeclaredConstructor().newInstance();
      } catch (Exception _) {
        // krunky structure, but the easiest way to deal with the
        // exception.
        def = new DefaultFECCodeFactory();
      }
    }
    return def;
  }
}
