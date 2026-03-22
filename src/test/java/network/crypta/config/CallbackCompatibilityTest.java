package network.crypta.config;

import network.crypta.node.ProgramDirectory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("deprecation")
class CallbackCompatibilityTest {
  private static final Option.Meta META = new Option.Meta(1, false, false, "sd", "ld");

  @Test
  void newCallbackTypesRemainAssignableToLegacyCallbacks() {
    assertTrue(
        network.crypta.support.api.BooleanCallback.class.isAssignableFrom(
            network.crypta.config.BooleanCallback.class));
    assertTrue(
        network.crypta.support.api.IntCallback.class.isAssignableFrom(
            network.crypta.config.IntCallback.class));
    assertTrue(
        network.crypta.support.api.LongCallback.class.isAssignableFrom(
            network.crypta.config.LongCallback.class));
    assertTrue(
        network.crypta.support.api.ShortCallback.class.isAssignableFrom(
            network.crypta.config.ShortCallback.class));
    assertTrue(
        network.crypta.support.api.StringCallback.class.isAssignableFrom(
            network.crypta.config.StringCallback.class));
    assertTrue(
        network.crypta.support.api.StringArrCallback.class.isAssignableFrom(
            network.crypta.config.StringArrCallback.class));
  }

  @Test
  void subConfigRetainsLegacyRegisterDescriptors() {
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                int.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                long.class,
                Option.Meta.class,
                network.crypta.support.api.LongCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                int.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class,
                Dimension.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.LongCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                boolean.class,
                Option.Meta.class,
                network.crypta.support.api.BooleanCallback.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.StringCallback.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                short.class,
                Option.Meta.class,
                network.crypta.support.api.ShortCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            SubConfig.class.getMethod(
                "register",
                String.class,
                String[].class,
                Option.Meta.class,
                network.crypta.support.api.StringArrCallback.class));
  }

  @Test
  void publicOptionConstructorsRetainLegacyCallbackDescriptors() {
    assertDoesNotThrow(
        () ->
            BandwidthOption.class.getConstructor(
                SubConfig.class,
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class));
    assertDoesNotThrow(
        () ->
            BandwidthOption.class.getConstructor(
                SubConfig.class,
                String.class,
                Integer.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class));
    assertDoesNotThrow(
        () ->
            BooleanOption.class.getConstructor(
                SubConfig.class,
                String.class,
                boolean.class,
                Option.Meta.class,
                network.crypta.support.api.BooleanCallback.class));
    assertDoesNotThrow(
        () ->
            IntOption.class.getConstructor(
                SubConfig.class,
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class,
                Dimension.class));
    assertDoesNotThrow(
        () ->
            IntOption.class.getConstructor(
                SubConfig.class,
                String.class,
                Integer.class,
                Option.Meta.class,
                network.crypta.support.api.IntCallback.class,
                Dimension.class));
    assertDoesNotThrow(
        () ->
            LongOption.class.getConstructor(
                SubConfig.class,
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.LongCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            LongOption.class.getConstructor(
                SubConfig.class,
                String.class,
                Long.class,
                Option.Meta.class,
                network.crypta.support.api.LongCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            ShortOption.class.getConstructor(
                SubConfig.class,
                String.class,
                short.class,
                Option.Meta.class,
                network.crypta.support.api.ShortCallback.class,
                boolean.class));
    assertDoesNotThrow(
        () ->
            StringOption.class.getConstructor(
                SubConfig.class,
                String.class,
                String.class,
                Option.Meta.class,
                network.crypta.support.api.StringCallback.class));
    assertDoesNotThrow(
        () ->
            StringArrOption.class.getConstructor(
                SubConfig.class,
                String.class,
                String[].class,
                Option.Meta.class,
                network.crypta.support.api.StringArrCallback.class));
  }

  @Test
  void legacyBooleanCallbackFactoryRemainsAvailable() {
    network.crypta.support.api.BooleanCallback callback =
        network.crypta.support.api.BooleanCallback.from(() -> true, _ -> {});

    assertInstanceOf(network.crypta.support.api.BooleanCallback.class, callback);
    assertInstanceOf(network.crypta.config.BooleanCallback.class, callback);
  }

  @Test
  void programDirectoryRetainsLegacyStringCallbackDescriptor() throws NoSuchMethodException {
    assertSame(
        network.crypta.support.api.StringCallback.class,
        ProgramDirectory.class.getMethod("getStringCallback").getReturnType());
    assertTrue(
        network.crypta.support.api.StringCallback.class.isAssignableFrom(
            ProgramDirectory.DirectoryCallback.class));
    assertTrue(
        network.crypta.support.api.StringCallback.class.isAssignableFrom(
            ProgramDirectory.RWDirectoryCallback.class));
  }

  @Test
  void programDirectoryCallbacksRemainVisibleThroughBothStringCallbackPackages() {
    ProgramDirectory readOnly = new ProgramDirectory();
    ProgramDirectory readWrite = new ProgramDirectory("compatibility.move.error");

    assertInstanceOf(network.crypta.support.api.StringCallback.class, readOnly.getStringCallback());
    assertInstanceOf(network.crypta.config.StringCallback.class, readOnly.getStringCallback());
    assertInstanceOf(
        network.crypta.support.api.StringCallback.class, readWrite.getStringCallback());
    assertInstanceOf(network.crypta.config.StringCallback.class, readWrite.getStringCallback());
  }

  @Test
  void nullCallbacksRemainAssignableToLegacyBridgeTypes() {
    assertTrue(
        network.crypta.support.api.BooleanCallback.class.isAssignableFrom(
            NullBooleanCallback.class));
    assertTrue(
        network.crypta.support.api.IntCallback.class.isAssignableFrom(NullIntCallback.class));
    assertTrue(
        network.crypta.support.api.LongCallback.class.isAssignableFrom(NullLongCallback.class));
    assertTrue(
        network.crypta.support.api.ShortCallback.class.isAssignableFrom(NullShortCallback.class));
    assertTrue(
        network.crypta.support.api.StringCallback.class.isAssignableFrom(NullStringCallback.class));
  }

  @Test
  void optionsUsingNewCallbacksExposeLegacyAssignableRuntimeInstancesAcrossFamilies() {
    Config config = new Config();
    SubConfig subConfig = config.createSubConfig("compat");
    BooleanCallback booleanCallback =
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return true;
          }

          @Override
          public void set(Boolean value) {}
        };
    IntCallback intCallback =
        new IntCallback() {
          @Override
          public Integer get() {
            return 123;
          }

          @Override
          public void set(Integer value) {}
        };
    IntCallback bandwidthCallback =
        new IntCallback() {
          @Override
          public Integer get() {
            return 2048;
          }

          @Override
          public void set(Integer value) {}
        };
    LongCallback longCallback =
        new LongCallback() {
          @Override
          public Long get() {
            return 456L;
          }

          @Override
          public void set(Long value) {}
        };
    ShortCallback shortCallback =
        new ShortCallback() {
          @Override
          public Short get() {
            return 7;
          }

          @Override
          public void set(Short value) {}
        };
    StringCallback stringCallback =
        new StringCallback() {
          @Override
          public String get() {
            return "value";
          }

          @Override
          public void set(String value) {}
        };
    StringArrCallback stringArrCallback =
        new StringArrCallback() {
          @Override
          public String[] get() {
            return new String[] {"value"};
          }

          @Override
          public void set(String[] value) {}
        };

    assertLegacyRuntimeCallback(
        new BooleanOption(subConfig, "flag", true, META, booleanCallback),
        booleanCallback,
        network.crypta.support.api.BooleanCallback.class);
    assertLegacyRuntimeCallback(
        new IntOption(subConfig, "count", 123, META, intCallback, Dimension.NOT),
        intCallback,
        network.crypta.support.api.IntCallback.class);
    assertLegacyRuntimeCallback(
        new BandwidthOption(subConfig, "bandwidth", 2048, META, bandwidthCallback),
        bandwidthCallback,
        network.crypta.support.api.IntCallback.class);
    assertLegacyRuntimeCallback(
        new LongOption(subConfig, "duration", 456L, META, longCallback, false),
        longCallback,
        network.crypta.support.api.LongCallback.class);
    assertLegacyRuntimeCallback(
        new ShortOption(subConfig, "small", (short) 7, META, shortCallback, false),
        shortCallback,
        network.crypta.support.api.ShortCallback.class);
    assertLegacyRuntimeCallback(
        new StringOption(subConfig, "path", "value", META, stringCallback),
        stringCallback,
        network.crypta.support.api.StringCallback.class);
    assertLegacyRuntimeCallback(
        new StringArrOption(subConfig, "list", new String[] {"value"}, META, stringArrCallback),
        stringArrCallback,
        network.crypta.support.api.StringArrCallback.class);
  }

  @Test
  void legacyOptionConstructorsExposeCallbacksThroughBothPackagesAcrossFamilies() {
    Config config = new Config();
    SubConfig subConfig = config.createSubConfig("compat");
    network.crypta.support.api.BooleanCallback booleanCallback =
        new network.crypta.support.api.BooleanCallback() {
          @Override
          public Boolean get() {
            return true;
          }

          @Override
          public void set(Boolean value) {}
        };
    network.crypta.support.api.IntCallback intCallback =
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 123;
          }

          @Override
          public void set(Integer value) {}
        };
    network.crypta.support.api.IntCallback bandwidthCallback =
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 2048;
          }

          @Override
          public void set(Integer value) {}
        };
    network.crypta.support.api.LongCallback longCallback =
        new network.crypta.support.api.LongCallback() {
          @Override
          public Long get() {
            return 456L;
          }

          @Override
          public void set(Long value) {}
        };
    network.crypta.support.api.ShortCallback shortCallback =
        new network.crypta.support.api.ShortCallback() {
          @Override
          public Short get() {
            return 7;
          }

          @Override
          public void set(Short value) {}
        };
    network.crypta.support.api.StringCallback stringCallback =
        new network.crypta.support.api.StringCallback() {
          @Override
          public String get() {
            return "value";
          }

          @Override
          public void set(String value) {}
        };
    network.crypta.support.api.StringArrCallback stringArrCallback =
        new network.crypta.support.api.StringArrCallback() {
          @Override
          public String[] get() {
            return new String[] {"value"};
          }

          @Override
          public void set(String[] value) {}
        };

    assertBridgedRuntimeCallback(
        new BooleanOption(subConfig, "flag", true, META, booleanCallback),
        booleanCallback,
        network.crypta.support.api.BooleanCallback.class,
        network.crypta.config.BooleanCallback.class);
    assertBridgedRuntimeCallback(
        new IntOption(subConfig, "count", 123, META, intCallback, Dimension.NOT),
        intCallback,
        network.crypta.support.api.IntCallback.class,
        network.crypta.config.IntCallback.class);
    assertBridgedRuntimeCallback(
        new BandwidthOption(subConfig, "bandwidth", 2048, META, bandwidthCallback),
        bandwidthCallback,
        network.crypta.support.api.IntCallback.class,
        network.crypta.config.IntCallback.class);
    assertBridgedRuntimeCallback(
        new LongOption(subConfig, "duration", 456L, META, longCallback, false),
        longCallback,
        network.crypta.support.api.LongCallback.class,
        network.crypta.config.LongCallback.class);
    assertBridgedRuntimeCallback(
        new ShortOption(subConfig, "small", (short) 7, META, shortCallback, false),
        shortCallback,
        network.crypta.support.api.ShortCallback.class,
        network.crypta.config.ShortCallback.class);
    assertBridgedRuntimeCallback(
        new StringOption(subConfig, "path", "value", META, stringCallback),
        stringCallback,
        network.crypta.support.api.StringCallback.class,
        network.crypta.config.StringCallback.class);
    assertBridgedRuntimeCallback(
        new StringArrOption(subConfig, "list", new String[] {"value"}, META, stringArrCallback),
        stringArrCallback,
        network.crypta.support.api.StringArrCallback.class,
        network.crypta.config.StringArrCallback.class);
  }

  @Test
  void legacyRegisterOverloadsExposeCallbacksThroughBothPackagesAcrossFamilies() {
    Config config = new Config();
    SubConfig subConfig = config.createSubConfig("compat");
    network.crypta.support.api.BooleanCallback booleanCallback =
        new network.crypta.support.api.BooleanCallback() {
          @Override
          public Boolean get() {
            return true;
          }

          @Override
          public void set(Boolean value) {}
        };
    network.crypta.support.api.IntCallback intCallback =
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 1;
          }

          @Override
          public void set(Integer value) {}
        };
    network.crypta.support.api.IntCallback bandwidthCallback =
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 2048;
          }

          @Override
          public void set(Integer value) {}
        };
    network.crypta.support.api.IntCallback bandwidthStringCallback =
        new network.crypta.support.api.IntCallback() {
          @Override
          public Integer get() {
            return 4096;
          }

          @Override
          public void set(Integer value) {}
        };
    network.crypta.support.api.LongCallback longCallback =
        new network.crypta.support.api.LongCallback() {
          @Override
          public Long get() {
            return 2L;
          }

          @Override
          public void set(Long value) {}
        };
    network.crypta.support.api.LongCallback longStringCallback =
        new network.crypta.support.api.LongCallback() {
          @Override
          public Long get() {
            return 3L;
          }

          @Override
          public void set(Long value) {}
        };
    network.crypta.support.api.ShortCallback shortCallback =
        new network.crypta.support.api.ShortCallback() {
          @Override
          public Short get() {
            return 4;
          }

          @Override
          public void set(Short value) {}
        };
    network.crypta.support.api.StringCallback stringCallback =
        new network.crypta.support.api.StringCallback() {
          @Override
          public String get() {
            return "value";
          }

          @Override
          public void set(String value) {}
        };
    network.crypta.support.api.StringArrCallback stringArrCallback =
        new network.crypta.support.api.StringArrCallback() {
          @Override
          public String[] get() {
            return new String[] {"value"};
          }

          @Override
          public void set(String[] value) {}
        };

    subConfig.register("flag", true, META, booleanCallback);
    subConfig.register("count", 1, META, intCallback, false);
    subConfig.register("bandwidth", 2048, META, bandwidthCallback);
    subConfig.register("bandwidthText", "4096", META, bandwidthStringCallback);
    subConfig.register("duration", 2L, META, longCallback, false);
    subConfig.register("durationText", "3", META, longStringCallback, false);
    subConfig.register("small", (short) 4, META, shortCallback, false);
    subConfig.register("path", "value", META, stringCallback);
    subConfig.register("list", new String[] {"value"}, META, stringArrCallback);

    assertBridgedRuntimeCallback(
        subConfig.getOption("flag"),
        booleanCallback,
        network.crypta.support.api.BooleanCallback.class,
        network.crypta.config.BooleanCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("count"),
        intCallback,
        network.crypta.support.api.IntCallback.class,
        network.crypta.config.IntCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("bandwidth"),
        bandwidthCallback,
        network.crypta.support.api.IntCallback.class,
        network.crypta.config.IntCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("bandwidthText"),
        bandwidthStringCallback,
        network.crypta.support.api.IntCallback.class,
        network.crypta.config.IntCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("duration"),
        longCallback,
        network.crypta.support.api.LongCallback.class,
        network.crypta.config.LongCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("durationText"),
        longStringCallback,
        network.crypta.support.api.LongCallback.class,
        network.crypta.config.LongCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("small"),
        shortCallback,
        network.crypta.support.api.ShortCallback.class,
        network.crypta.config.ShortCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("path"),
        stringCallback,
        network.crypta.support.api.StringCallback.class,
        network.crypta.config.StringCallback.class);
    assertBridgedRuntimeCallback(
        subConfig.getOption("list"),
        stringArrCallback,
        network.crypta.support.api.StringArrCallback.class,
        network.crypta.config.StringArrCallback.class);
  }

  private static void assertLegacyRuntimeCallback(
      Option<?> option, Object callback, Class<?> legacyType) {
    assertSame(callback, option.getCallback());
    assertInstanceOf(legacyType, option.getCallback());
  }

  private static void assertBridgedRuntimeCallback(
      Option<?> option, Object callback, Class<?> legacyType, Class<?> configType) {
    assertNotSame(callback, option.getCallback());
    assertInstanceOf(legacyType, option.getCallback());
    assertInstanceOf(configType, option.getCallback());
  }
}
