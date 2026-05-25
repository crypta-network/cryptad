package network.crypta.platform.api.appdata;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ResourceLock(Resources.SYSTEM_PROPERTIES)
class AppDataStoreConfigTest {
  private static final List<String> PROPERTY_NAMES =
      List.of(
          "cryptad.appData.maxRecordBytes",
          "cryptad.appData.maxRecordsPerApp",
          "cryptad.appData.maxNamespacesPerApp",
          "cryptad.appData.maxExportBytes",
          "cryptad.appData.maxImportBytes",
          "cryptad.appData.maxMigrationHistory");

  @Test
  void loadFromSystem_whenPropertiesAreUnset_returnsDefaults() {
    Map<String, String> previousValues = captureProperties();
    try {
      PROPERTY_NAMES.forEach(System::clearProperty);

      AppDataStoreConfig config = AppDataStoreConfig.loadFromSystem();

      assertEquals(AppDataStoreConfig.defaults(), config);
    } finally {
      restoreProperties(previousValues);
    }
  }

  @Test
  void loadFromSystem_whenPropertiesArePositive_returnsOverrides() {
    Map<String, String> previousValues = captureProperties();
    try {
      System.setProperty("cryptad.appData.maxRecordBytes", "16");
      System.setProperty("cryptad.appData.maxRecordsPerApp", "17");
      System.setProperty("cryptad.appData.maxNamespacesPerApp", "18");
      System.setProperty("cryptad.appData.maxExportBytes", "19");
      System.setProperty("cryptad.appData.maxImportBytes", "20");
      System.setProperty("cryptad.appData.maxMigrationHistory", "21");

      AppDataStoreConfig config = AppDataStoreConfig.loadFromSystem();

      assertEquals(new AppDataStoreConfig(16, 17, 18, 19, 20, 21), config);
    } finally {
      restoreProperties(previousValues);
    }
  }

  @Test
  void loadFromSystem_whenPropertiesAreInvalid_returnsDefaults() {
    Map<String, String> previousValues = captureProperties();
    try {
      System.setProperty("cryptad.appData.maxRecordBytes", "0");
      System.setProperty("cryptad.appData.maxRecordsPerApp", "-1");
      System.setProperty("cryptad.appData.maxNamespacesPerApp", " ");
      System.setProperty("cryptad.appData.maxExportBytes", "invalid");
      System.setProperty("cryptad.appData.maxImportBytes", "-2147483648");
      System.setProperty("cryptad.appData.maxMigrationHistory", "");

      AppDataStoreConfig config = AppDataStoreConfig.loadFromSystem();

      assertEquals(AppDataStoreConfig.defaults(), config);
    } finally {
      restoreProperties(previousValues);
    }
  }

  @Test
  void constructor_whenLimitIsNotPositive_rejectsConfig() {
    assertThrows(IllegalArgumentException.class, () -> new AppDataStoreConfig(1, 1, 1, 1, 1, 0));
  }

  private static Map<String, String> captureProperties() {
    Map<String, String> values = LinkedHashMap.newLinkedHashMap(PROPERTY_NAMES.size());
    for (String propertyName : PROPERTY_NAMES) {
      values.put(propertyName, System.getProperty(propertyName));
    }
    return values;
  }

  private static void restoreProperties(Map<String, String> values) {
    values.forEach(AppDataStoreConfigTest::restoreProperty);
  }

  private static void restoreProperty(String propertyName, String value) {
    if (value == null) {
      System.clearProperty(propertyName);
    } else {
      System.setProperty(propertyName, value);
    }
  }
}
