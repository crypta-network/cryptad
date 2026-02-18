package org.spaceroots.mantissa.random;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class UniformRandomGeneratorTest {

  @Test
  void nextDouble_whenTwoGeneratorsSameIntSeed_producesSameSequence() {
    int seed = 12345;
    UniformRandomGenerator first = new UniformRandomGenerator(seed);
    UniformRandomGenerator second = new UniformRandomGenerator(seed);

    double[] firstValues =
        IntStream.range(0, 5).mapToDouble(ignored -> first.nextDouble()).toArray();
    double[] secondValues =
        IntStream.range(0, 5).mapToDouble(ignored -> second.nextDouble()).toArray();

    for (int i = 0; i < firstValues.length; i++) {
      assertEquals(firstValues[i], secondValues[i], 0.0);
    }
  }

  @Test
  void nextDouble_whenTwoGeneratorsSameLongSeed_producesSameSequence() {
    long seed = 9876543210L;
    UniformRandomGenerator first = new UniformRandomGenerator(seed);
    UniformRandomGenerator second = new UniformRandomGenerator(seed);

    double[] firstValues =
        IntStream.range(0, 5).mapToDouble(ignored -> first.nextDouble()).toArray();
    double[] secondValues =
        IntStream.range(0, 5).mapToDouble(ignored -> second.nextDouble()).toArray();

    for (int i = 0; i < firstValues.length; i++) {
      assertEquals(firstValues[i], secondValues[i], 0.0);
    }
  }

  @Test
  void nextDouble_whenTwoGeneratorsSameSeedArray_producesSameSequence() {
    int[] seed = new int[] {1, 2, 3, 4};
    UniformRandomGenerator first = new UniformRandomGenerator(seed.clone());
    UniformRandomGenerator second = new UniformRandomGenerator(seed.clone());

    double[] firstValues =
        IntStream.range(0, 5).mapToDouble(ignored -> first.nextDouble()).toArray();
    double[] secondValues =
        IntStream.range(0, 5).mapToDouble(ignored -> second.nextDouble()).toArray();

    for (int i = 0; i < firstValues.length; i++) {
      assertEquals(firstValues[i], secondValues[i], 0.0);
    }
  }

  @Test
  void constructor_whenSeedArrayNull_doesNotThrowAndProducesFiniteValue() {
    UniformRandomGenerator generator = new UniformRandomGenerator(null);

    double value = generator.nextDouble();

    assertTrue(Double.isFinite(value));
  }

  @ParameterizedTest
  @CsvSource({"0.0", "0.5", "0.75", "0.999999"})
  void nextDouble_whenUnderlyingGeneratorMocked_appliesUniformNormalization(double underlying) {
    MersenneTwister mockedTwister = Mockito.mock(MersenneTwister.class);
    Mockito.when(mockedTwister.nextDouble()).thenReturn(underlying);

    UniformRandomGenerator generator = new UniformRandomGenerator(0);
    generator.generator = mockedTwister;

    double value = generator.nextDouble();

    double sqrt3 = Math.sqrt(3.0);
    double expected = 2.0 * sqrt3 * underlying - sqrt3;
    assertEquals(expected, value, 0.0);
    Mockito.verify(mockedTwister).nextDouble();
  }

  @Test
  void nextDouble_whenSampledManyTimes_staysWithinBoundsAndHasExpectedMoments() {
    UniformRandomGenerator generator = new UniformRandomGenerator(24680);
    double sqrt3 = Math.sqrt(3.0);
    int samples = 20_000;

    double min = Double.POSITIVE_INFINITY;
    double max = Double.NEGATIVE_INFINITY;
    double sum = 0.0;
    double sumSq = 0.0;

    for (int i = 0; i < samples; i++) {
      double value = generator.nextDouble();
      assertTrue(value >= -sqrt3 - 1e-15);
      assertTrue(value <= sqrt3 + 1e-15);

      min = Math.min(min, value);
      max = Math.max(max, value);
      sum += value;
      sumSq += value * value;
    }

    double mean = sum / samples;
    double variance = (sumSq / samples) - mean * mean;
    double standardDeviation = Math.sqrt(variance);

    assertEquals(0.0, mean, 0.02);
    assertEquals(1.0, standardDeviation, 0.03);
    assertTrue(min < -1.0);
    assertTrue(max > 1.0);
  }

  @Test
  void serialization_whenRoundTripped_preservesSequence() throws Exception {
    UniformRandomGenerator original = new UniformRandomGenerator(13579);

    IntStream.range(0, 10).forEach(ignored -> original.nextDouble());

    UniformRandomGenerator restored = serializeRoundTrip(original);

    for (int i = 0; i < 5; i++) {
      assertEquals(original.nextDouble(), restored.nextDouble(), 0.0);
    }
  }

  private static UniformRandomGenerator serializeRoundTrip(UniformRandomGenerator generator)
      throws Exception {
    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    try (ObjectOutputStream out = new ObjectOutputStream(buffer)) {
      out.writeObject(generator);
    }

    try (ObjectInputStream in =
        new ObjectInputStream(new ByteArrayInputStream(buffer.toByteArray()))) {
      return (UniformRandomGenerator) in.readObject();
    }
  }
}
