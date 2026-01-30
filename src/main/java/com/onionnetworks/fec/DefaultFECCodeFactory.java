package com.onionnetworks.fec;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Constructor;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Default factory that discovers and instantiates forward error correction (FEC) code
 * implementations declared in {@link FECCodeFactory} properties.
 *
 * <p>The factory reads a configurable properties file (default: {@code lib/fec.properties}) to
 * determine which code classes are available, how many bits they operate on, and how they should be
 * constructed. Callers obtain instances by requesting a code for a specific {@code k} and {@code n}
 * value, and the factory iterates through the known implementations until it finds a compatible
 * constructor. All property lookups are synchronized to guard against concurrent mutation, and code
 * instantiation is performed lazily so unused implementations do not incur startup cost.
 *
 * <p>Usage typically follows a simple pattern: initialize the factory, ensure the desired codes are
 * listed in the properties file, and then invoke {@link #createFECCode(int, int)} for each
 * requested set of parameters. The factory maintains separate constructor lists for 8-bit and
 * 16-bit implementations to avoid returning wider codes when narrow ones are requested. It does not
 * currently cache instances; every call builds a fresh code object. The class is safe to share
 * across threads because its public methods are synchronized and state is populated during
 * construction.
 *
 * <ul>
 *   <li>Responsibilities: load FEC metadata, select constructors, and create code instances.
 *   <li>Notable behaviors: enforces argument ranges, tolerates missing implementations by logging
 *       warnings, and returns {@code null} when no compatible code is found.
 * </ul>
 *
 * @author Justin F. Chapweske (justin@chapweske.com)
 * @see FECCodeFactory
 */
@SuppressWarnings("java:S1181")
public class DefaultFECCodeFactory extends FECCodeFactory {

  /**
   * Constructors for FEC implementations that operate on 8-bit symbols, populated from the
   * properties file during construction and never mutated afterward.
   */
  protected final List<Constructor<? extends FECCode>> eightBitCodes = new ArrayList<>();

  /**
   * Constructors for FEC implementations that operate on 16-bit symbols, kept separate to avoid
   * widening results when callers request byte-sized codes.
   */
  protected final List<Constructor<? extends FECCode>> sixteenBitCodes = new ArrayList<>();

  /**
   * Properties defining available FEC codes, keyed by {@code com.onionnetworks.fec.*}; loaded once
   * from the configured resource path and consulted for every lookup.
   */
  protected Properties fecProperties;

  private static final Logger LOGGER = Logger.getLogger(DefaultFECCodeFactory.class.getName());

  /**
   * Creates a factory and eagerly loads the FEC metadata defined in the configured properties
   * resource so subsequent lookups do not touch the file system.
   *
   * <p>The constructor is intended to be inexpensive: it parses keys, reflects the available code
   * classes, and populates constructor lists but does not instantiate any {@link FECCode}
   * instances. All failures to read the properties resource surface as {@link
   * IllegalStateException} to make misconfiguration obvious.
   */
  public DefaultFECCodeFactory() {
    // Load in the properties file.
    fecProperties = new Properties();
    String propertyPath =
        System.getProperty(
            "com.onionnetworks.fec.defaultfeccodefactorypropertiesfile", "lib/fec.properties");
    try (InputStream propertyStream =
        DefaultFECCodeFactory.class.getClassLoader().getResourceAsStream(propertyPath)) {
      if (propertyStream == null) {
        throw new IllegalStateException("Unable to load /" + propertyPath);
      }
      fecProperties.load(propertyStream);
    } catch (IOException e) {
      throw new IllegalStateException("Unable to load /" + propertyPath, e);
    }

    // Parse the keys
    StringTokenizer st = new StringTokenizer(getProperty("com.onionnetworks.fec.keys"), ",");

    // Load the codes into the HashMaps.
    while (st.hasMoreTokens()) {
      String key = st.nextToken();
      try {
        Class<?> codeClass = Class.forName(getProperty("com.onionnetworks.fec." + key + ".class"));
        Constructor<? extends FECCode> constructor =
            codeClass.asSubclass(FECCode.class).getConstructor(int.class, int.class);
        String numBits = getProperty("com.onionnetworks.fec." + key + ".bits");
        if ("8".equals(numBits)) {
          eightBitCodes.add(constructor);
        } else if ("16".equals(numBits)) {
          sixteenBitCodes.add(constructor);
        } else {
          throw new IllegalArgumentException("Only 8 and 16 bit codes are currently supported");
        }
      } catch (Throwable t) {
        LOGGER.log(Level.WARNING, t.getMessage(), t);
      }
    }
  }

  /**
   * Retrieves a configuration value, preferring system properties before falling back to the loaded
   * factory properties.
   *
   * <p>This method is synchronized to align with the factory's other synchronized entry points,
   * keeping lookup behavior predictable when callers adjust system properties at runtime. It
   * returns {@code null} only when neither source contains the requested key.
   *
   * @param key fully qualified property name to resolve; must not be {@code null}.
   * @return resolved property value or {@code null} when no override or default is present.
   */
  protected synchronized String getProperty(String key) {
    String result = System.getProperty(key);
    if (result == null) {
      result = fecProperties.getProperty(key);
    }
    return result;
  }

  /**
   * Creates an FEC code instance for the requested {@code k} and {@code n} parameters using the
   * first compatible constructor discovered in the configured code list.
   *
   * <p>The method enforces argument bounds of {@code 1 <= k <= n <= 65536} and selects 8-bit code
   * constructors for small symbol counts when available, falling back to 16-bit implementations
   * otherwise. If constructor invocation fails, the factory logs the exception and continues
   * probing remaining candidates. A {@code null} return value signals that no usable implementation
   * was found for the supplied parameters.
   *
   * @param k number of source symbols; valid range is 1 through 65536 inclusive.
   * @param n total number of encoded symbols requested; must be at least {@code k} and at most
   *     65536.
   * @return newly constructed {@link FECCode} tailored to the arguments, or {@code null} when no
   *     compatible implementation is available.
   * @throws IllegalArgumentException if {@code k} or {@code n} fall outside the documented bounds
   *     or {@code n} is smaller than {@code k}.
   */
  @Override
  public synchronized FECCode createFECCode(int k, int n) {
    //noinspection ConditionCoveredByFurtherCondition
    if (k < 1 || k > 65536 || n < k || n > 65536) {
      throw new IllegalArgumentException(
          "k and n must be between 1 and 65536 and n must not be "
              + "smaller than k: k="
              + k
              + ",n="
              + n);
    }

    Iterator<Constructor<? extends FECCode>> it;
    if (n <= 256 && !eightBitCodes.isEmpty()) {
      it = eightBitCodes.iterator();
    } else {
      it = sixteenBitCodes.iterator();
    }
    while (it.hasNext()) {
      try {
        Constructor<? extends FECCode> constructor = it.next();
        return constructor.newInstance(k, n);
      } catch (Throwable doh) {
        LOGGER.log(Level.WARNING, doh.getMessage(), doh);
      }
    }
    return null;
  }
}
