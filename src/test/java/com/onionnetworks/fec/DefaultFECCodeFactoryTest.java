package com.onionnetworks.fec;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class DefaultFECCodeFactoryTest {

  private final Map<String, String> previousProperties = new HashMap<>();

  @AfterEach
  void restoreSystemProperties() {
    previousProperties.forEach(
        (key, value) -> {
          if (value == null) {
            System.clearProperty(key);
          } else {
            System.setProperty(key, value);
          }
        });
    previousProperties.clear();
  }

  @Test
  void createFECCode_whenNWithinEightBitRange_usesEightBitConstructor() {
    configureDummyCodes();

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    try (FECCode code = factory.createFECCode(3, 10)) {
      assertInstanceOf(DummyEightBitCode.class, code);
    }
  }

  @Test
  void createFECCode_whenNAboveEightBitRange_usesSixteenBitConstructor() {
    configureDummyCodes();

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    try (FECCode code = factory.createFECCode(3, 300)) {
      assertInstanceOf(DummySixteenBitCode.class, code);
    }
  }

  @Test
  @SuppressWarnings("EmptyTryBlock")
  void createFECCode_whenParametersOutOfRange_throwsIllegalArgumentException() {
    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.createFECCode(0, 1)) {
            // unreachable
          }
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.createFECCode(4, 3)) {
            // unreachable
          }
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.createFECCode(1, 70000)) {
            // unreachable
          }
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = factory.createFECCode(70000, 70000)) {
            // unreachable
          }
        });
  }

  @Test
  void createFECCode_whenNoCodesConfigured_returnsNull() {
    setSystemProperty("com.onionnetworks.fec.keys", "");

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    FECCode code = factory.createFECCode(1, 1);

    assertNull(code);
  }

  @Test
  void createFECCode_whenFirstConstructorFails_usesNextConstructor() {
    setSystemProperty("com.onionnetworks.fec.keys", "failing,good");
    setSystemProperty("com.onionnetworks.fec.failing.class", FailingEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.failing.bits", "8");
    setSystemProperty("com.onionnetworks.fec.good.class", DummyEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.good.bits", "8");

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    try (FECCode code = factory.createFECCode(2, 10)) {
      assertInstanceOf(DummyEightBitCode.class, code);
    }
  }

  @Test
  void createFECCode_whenFirstConstructorThrowsError_usesNextConstructor() {
    setSystemProperty("com.onionnetworks.fec.keys", "err,good");
    setSystemProperty("com.onionnetworks.fec.err.class", FailingErrorEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.err.bits", "8");
    setSystemProperty("com.onionnetworks.fec.good.class", DummyEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.good.bits", "8");

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    try (FECCode code = factory.createFECCode(2, 10)) {
      assertInstanceOf(DummyEightBitCode.class, code);
    }
  }

  @Test
  void constructor_whenCodecClassThrowsError_skipsAndLoadsNext() {
    setSystemProperty("com.onionnetworks.fec.keys", "err,good");
    setSystemProperty(
        "com.onionnetworks.fec.err.class", FailingLoadErrorEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.err.bits", "8");
    setSystemProperty("com.onionnetworks.fec.good.class", DummyEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.good.bits", "8");
    setSystemProperty("com.onionnetworks.fec.failLoadError", "true");

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();

    try (FECCode code = factory.createFECCode(2, 10)) {
      assertInstanceOf(DummyEightBitCode.class, code);
    }
  }

  @Test
  void getProperty_whenSystemPropertyPresent_returnsSystemValue() {
    setSystemProperty("com.onionnetworks.fec.keys", "");
    setSystemProperty("custom.key", "systemValue");

    DefaultFECCodeFactory factory = new DefaultFECCodeFactory();
    factory.fecProperties.setProperty("custom.key", "fileValue");
    String value = factory.getProperty("custom.key");

    assertEquals("systemValue", value);
  }

  private void configureDummyCodes() {
    setSystemProperty("com.onionnetworks.fec.keys", "dummy8,dummy16");
    setSystemProperty("com.onionnetworks.fec.dummy8.class", DummyEightBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.dummy8.bits", "8");
    setSystemProperty("com.onionnetworks.fec.dummy16.class", DummySixteenBitCode.class.getName());
    setSystemProperty("com.onionnetworks.fec.dummy16.bits", "16");
  }

  private void setSystemProperty(String key, String value) {
    previousProperties.putIfAbsent(key, System.getProperty(key));
    if (value == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, value);
    }
  }

  /** Simple deterministic 8-bit stub. */
  public static class DummyEightBitCode extends FECCode {
    public DummyEightBitCode(int k, int n) {
      super(k, n);
    }

    @Override
    protected void encode(
        byte[][] src,
        int[] srcOff,
        byte[][] repair,
        int[] repairOff,
        int[] index,
        int packetLength) {
      // No-op: test stub only needs to satisfy abstract contract, not perform encoding.
    }

    @Override
    protected void decode(
        byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled) {
      // No-op: decoding behavior is irrelevant for factory selection tests.
    }
  }

  /** Simple deterministic 16-bit stub. */
  public static class DummySixteenBitCode extends FECCode {
    public DummySixteenBitCode(int k, int n) {
      super(k, n);
    }

    @Override
    protected void encode(
        byte[][] src,
        int[] srcOff,
        byte[][] repair,
        int[] repairOff,
        int[] index,
        int packetLength) {
      // No-op: test double used only to verify 16-bit constructor discovery.
    }

    @Override
    protected void decode(
        byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled) {
      // No-op: test double used only to verify 16-bit constructor discovery.
    }
  }

  /** Stub that fails at construction to exercise fallback behavior. */
  public static class FailingEightBitCode extends FECCode {
    public FailingEightBitCode(int k, int n) {
      super(k, n);
      throw new IllegalStateException("boom");
    }

    @Override
    protected void encode(
        byte[][] src,
        int[] srcOff,
        byte[][] repair,
        int[] repairOff,
        int[] index,
        int packetLength) {
      // No-op: never reached because constructor throws; present to satisfy abstract API.
    }

    @Override
    protected void decode(
        byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled) {
      // No-op: never reached because constructor throws; present to satisfy abstract API.
    }
  }

  /** Stub that fails with an Error in the constructor to exercise Error fallback. */
  public static class FailingErrorEightBitCode extends FECCode {
    public FailingErrorEightBitCode(int k, int n) {
      super(k, n);
      throw new UnsatisfiedLinkError("native missing");
    }

    @Override
    protected void encode(
        byte[][] src,
        int[] srcOff,
        byte[][] repair,
        int[] repairOff,
        int[] index,
        int packetLength) {
      // No-op: never reached because constructor throws; present to satisfy abstract API.
    }

    @Override
    protected void decode(
        byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled) {
      // No-op: never reached because constructor throws; present to satisfy abstract API.
    }
  }

  /**
   * Stub whose static initializer raises an Error to simulate native load failures during class
   * init.
   */
  public static class FailingLoadErrorEightBitCode extends FECCode {
    static {
      // Simulate native dependency failure during class loading.
      if (Boolean.getBoolean("com.onionnetworks.fec.failLoadError")) {
        throw new UnsatisfiedLinkError("failed to load native codec");
      }
    }

    public FailingLoadErrorEightBitCode(int k, int n) {
      super(k, n);
    }

    @Override
    protected void encode(
        byte[][] src,
        int[] srcOff,
        byte[][] repair,
        int[] repairOff,
        int[] index,
        int packetLength) {
      // No-op: never reached; class loading fails first.
    }

    @Override
    protected void decode(
        byte[][] pkts, int[] pktsOff, int[] index, int packetLength, boolean shuffled) {
      // No-op: never reached; class loading fails first.
    }
  }
}
