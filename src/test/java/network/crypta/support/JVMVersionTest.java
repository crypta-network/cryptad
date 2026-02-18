package network.crypta.support;

import com.sun.jna.Platform;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JVMVersionTest {

  @Test
  void isEOL_givenTooOldVersions_expectTrue() {
    assertTrue(JVMVersion.isEOL("1.6.0_32"));
    assertTrue(JVMVersion.isEOL("1.6"));
    assertTrue(JVMVersion.isEOL("1.5"));
    assertTrue(JVMVersion.isEOL("1.7.0_65"));
    assertTrue(JVMVersion.isEOL("1.7"));
  }

  @Test
  void needsLegacyUpdater_givenTooOldVersions_expectTrue() {
    assertTrue(JVMVersion.needsLegacyUpdater("1.6.0_32"));
    assertTrue(JVMVersion.needsLegacyUpdater("1.6"));
    assertTrue(JVMVersion.needsLegacyUpdater("1.5"));
    assertTrue(JVMVersion.needsLegacyUpdater("1.7.0_65"));
    assertTrue(JVMVersion.needsLegacyUpdater("1.7"));
  }

  @Test
  void isEOL_givenRecentEnoughVersions_expectFalse() {
    assertFalse(JVMVersion.isEOL("21"));
    assertFalse(JVMVersion.isEOL("21-ea"));
    assertFalse(JVMVersion.isEOL("22"));
  }

  @Test
  void needsLegacyUpdater_givenRecentEnoughVersions_expectFalse() {
    assertFalse(JVMVersion.needsLegacyUpdater("21"));
    assertFalse(JVMVersion.needsLegacyUpdater("21-ea"));
    assertFalse(JVMVersion.needsLegacyUpdater("22"));
  }

  @Test
  void thresholds_relativeOrdering_consistent() {
    // Being below the updater threshold implies EOL or equal to EOL threshold
    assertTrue(
        JVMVersion.compareVersion(JVMVersion.UPDATER_THRESHOLD, JVMVersion.EOL_THRESHOLD) <= 0);
  }

  @Test
  void oldnessChecks_whenNull_expectFalse() {
    assertFalse(JVMVersion.isEOL(null));
    assertFalse(JVMVersion.needsLegacyUpdater(null));
  }

  @Test
  void compareVersion_withOrderedList_expectCorrectSignumForAllPairs() {
    String[] orderedVersions =
        new String[] {
          "bogus", // Bogus versions are treated as 0.0.0_0
          "1.5",
          "1.6.0",
          "1.6.0_32",
          "1.7",
          "1.7.0_59",
          "1.7.0_65",
          "1.7.1",
          "1.7.1_1",
          "1.7.1_09",
          "1.7.1_65-rc4",
          "1.7.2-ea",
          "1.7.3_0",
          "1.8-beta",
          "9-ea",
          "9.0.1.0",
          "9.0.1.1.0.1-ea",
          "9.2",
          "10",
          "10.0.2"
        };

    for (int i = 0; i < orderedVersions.length; i++) {
      String v1 = orderedVersions[i];
      for (int j = 0; j < orderedVersions.length; j++) {
        String v2 = orderedVersions[j];
        int expected = Integer.signum(Integer.compare(i, j));
        int actual = Integer.signum(JVMVersion.compareVersion(v1, v2));
        assertEquals(expected, actual, v1 + " <> " + v2);
      }
    }
  }

  @Test
  void parse_whenVariousFormats_expectExpectedComponents() {
    assertArrayEquals(new int[] {0, 0, 0, 0}, JVMVersion.parse(null));
    assertArrayEquals(new int[] {0, 0, 0, 0}, JVMVersion.parse("bogus"));
    assertArrayEquals(new int[] {1, 0, 0, 0}, JVMVersion.parse("1"));
    assertArrayEquals(new int[] {1, 7, 1, 9}, JVMVersion.parse("1.7.1_09"));
    assertArrayEquals(new int[] {9, 0, 1, 1}, JVMVersion.parse("9.0.1.1.0.1-ea"));
    assertArrayEquals(new int[] {1, 2, 3, 4}, JVMVersion.parse("001.02.003_004"));
    assertArrayEquals(new int[] {9, 0, 0, 0}, JVMVersion.parse("9-ea"));
  }

  @Test
  void supportsModules_whenCurrentBelow19_expectFalse() {
    String prev = System.getProperty("java.version");
    try {
      System.setProperty("java.version", "1.8.0_202");
      assertFalse(JVMVersion.supportsModules());
    } finally {
      restoreProperty("java.version", prev);
    }
  }

  @Test
  void supportsModules_whenCurrentAtLeast19_expectTrue() {
    String prev = System.getProperty("java.version");
    try {
      System.setProperty("java.version", "9");
      assertTrue(JVMVersion.supportsModules());
      System.setProperty("java.version", "21");
      assertTrue(JVMVersion.supportsModules());
    } finally {
      restoreProperty("java.version", prev);
    }
  }

  @Test
  void is32Bit_whenOsArchX86_noModelProperty_expectTrue() {
    String prevArch = System.getProperty("os.arch");
    String prevModel = System.getProperty("sun.arch.data.model");
    try {
      System.setProperty("os.arch", "x86");
      System.clearProperty("sun.arch.data.model");
      assertTrue(JVMVersion.is32Bit());
    } finally {
      restoreProperty("os.arch", prevArch);
      restoreProperty("sun.arch.data.model", prevModel);
    }
  }

  @Test
  void is32Bit_whenModel32_expectTrueRegardlessOfArch() {
    String prevArch = System.getProperty("os.arch");
    String prevModel = System.getProperty("sun.arch.data.model");
    try {
      System.setProperty("os.arch", "amd64");
      System.setProperty("sun.arch.data.model", "32");
      assertTrue(JVMVersion.is32Bit());
    } finally {
      restoreProperty("os.arch", prevArch);
      restoreProperty("sun.arch.data.model", prevModel);
    }
  }

  @Test
  void is32Bit_whenArchX86_andModel64_expectTrueBecause32BitOs() {
    String prevArch = System.getProperty("os.arch");
    String prevModel = System.getProperty("sun.arch.data.model");
    try {
      System.setProperty("os.arch", "x86");
      System.setProperty("sun.arch.data.model", "64");
      assertTrue(JVMVersion.is32Bit());
    } finally {
      restoreProperty("os.arch", prevArch);
      restoreProperty("sun.arch.data.model", prevModel);
    }
  }

  @Test
  void is32Bit_whenArchNotX86_andModel64_expectFalse() {
    String prevArch = System.getProperty("os.arch");
    String prevModel = System.getProperty("sun.arch.data.model");
    try {
      System.setProperty("os.arch", "arm64");
      System.setProperty("sun.arch.data.model", "64");
      assertFalse(JVMVersion.is32Bit());
    } finally {
      restoreProperty("os.arch", prevArch);
      restoreProperty("sun.arch.data.model", prevModel);
    }
  }

  @Test
  void getCurrent_returnsSameAsSystemProperty() {
    String prev = System.getProperty("java.version");
    try {
      System.setProperty("java.version", "17.0.9");
      assertEquals("17.0.9", JVMVersion.getCurrent());
    } finally {
      restoreProperty("java.version", prev);
    }
  }

  @Test
  void isEOL_public_whenAndroid_expectFalseRegardlessOfVersion() {
    String prev = System.getProperty("java.version");
    try (MockedStatic<Platform> mocked = org.mockito.Mockito.mockStatic(Platform.class)) {
      mocked.when(Platform::isAndroid).thenReturn(true);
      System.setProperty("java.version", "1.6.0_45"); // would be EOL if not Android
      assertFalse(JVMVersion.isEOL());
    } finally {
      restoreProperty("java.version", prev);
    }
  }

  @Test
  void isEOL_public_whenNotAndroid_usesCurrentVersionProperty() {
    String prev = System.getProperty("java.version");
    try (MockedStatic<Platform> mocked = org.mockito.Mockito.mockStatic(Platform.class)) {
      mocked.when(Platform::isAndroid).thenReturn(false);

      System.setProperty("java.version", "1.7.0_80");
      assertTrue(JVMVersion.isEOL());

      System.setProperty("java.version", "21");
      assertFalse(JVMVersion.isEOL());
    } finally {
      restoreProperty("java.version", prev);
    }
  }

  private static void restoreProperty(String key, String previousValue) {
    if (previousValue == null) {
      System.clearProperty(key);
    } else {
      System.setProperty(key, previousValue);
    }
  }
}
