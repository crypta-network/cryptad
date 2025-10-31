package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class RequestClientBuilderTest {

  @Test
  @DisplayName("build_whenDefaults_expectNonPersistentNonRealtime")
  void build_whenDefaults_expectNonPersistentNonRealtime() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder();

    // Act
    RequestClient client = builder.build();

    // Assert
    assertAll(
        () -> assertFalse(client.persistent(), "Default persistent should be false"),
        () -> assertFalse(client.realTimeFlag(), "Default realTime should be false"));
  }

  @Test
  @DisplayName("persistent_whenCalled_expectTrue")
  void persistent_whenCalled_expectTrue() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder().persistent();

    // Act
    RequestClient client = builder.build();

    // Assert
    assertTrue(client.persistent(), "Persistent flag should be true when set via persistent()");
  }

  @Test
  @DisplayName("persistentFalse_afterTrue_expectFalse")
  void persistentFalse_afterTrue_expectFalse() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder().persistent(true).persistent(false);

    // Act
    RequestClient client = builder.build();

    // Assert
    assertFalse(client.persistent(), "Explicit persistent(false) should override previous true");
  }

  @Test
  @DisplayName("realTime_whenCalled_expectTrue")
  void realTime_whenCalled_expectTrue() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder().realTime();

    // Act
    RequestClient client = builder.build();

    // Assert
    assertTrue(client.realTimeFlag(), "Real-time flag should be true when set via realTime()");
  }

  @Test
  @DisplayName("realTimeFalse_afterTrue_expectFalse")
  void realTimeFalse_afterTrue_expectFalse() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder().realTime(true).realTime(false);

    // Act
    RequestClient client = builder.build();

    // Assert
    assertFalse(client.realTimeFlag(), "Explicit realTime(false) should override previous true");
  }

  @Test
  @DisplayName("build_reuseBuilder_expectSnapshotIndependence")
  void build_reuseBuilder_expectSnapshotIndependence() {
    // Arrange
    RequestClientBuilder builder = new RequestClientBuilder().persistent(true).realTime(false);
    RequestClient first = builder.build();

    // Mutate builder after first build
    builder.persistent(false).realTime(true);

    // Act
    RequestClient second = builder.build();

    // Assert
    assertAll(
        () -> assertTrue(first.persistent(), "First snapshot should retain persistent=true"),
        () -> assertFalse(first.realTimeFlag(), "First snapshot should retain realTime=false"),
        () -> assertFalse(second.persistent(), "Second snapshot should see persistent=false"),
        () -> assertTrue(second.realTimeFlag(), "Second snapshot should see realTime=true"));
  }

  @Test
  @DisplayName("fluent_whenChained_expectSameBuilderAndSettings")
  void fluent_whenChained_expectSameBuilderAndSettings() {
    // Arrange & Act
    RequestClientBuilder builder = new RequestClientBuilder();
    RequestClientBuilder b1 = builder.persistent();
    RequestClientBuilder b2 = builder.realTime();

    // Assert
    assertAll(
        () -> assertSame(builder, b1, "persistent() should return the same builder instance"),
        () -> assertSame(builder, b2, "realTime() should return the same builder instance"),
        () -> {
          RequestClient client = builder.build();
          assertAll(
              () -> assertTrue(client.persistent(), "Chained persistent() should be effective"),
              () -> assertTrue(client.realTimeFlag(), "Chained realTime() should be effective"));
        });
  }
}
