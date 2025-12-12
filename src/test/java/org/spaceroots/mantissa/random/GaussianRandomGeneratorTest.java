package org.spaceroots.mantissa.random;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class GaussianRandomGeneratorTest {

  @Test
  void nextDouble_whenTwoGeneratorsSameIntSeed_producesSameSequence() {
    int seed = 12345;
    GaussianRandomGenerator first = new GaussianRandomGenerator(seed);
    GaussianRandomGenerator second = new GaussianRandomGenerator(seed);

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
    GaussianRandomGenerator first = new GaussianRandomGenerator(seed);
    GaussianRandomGenerator second = new GaussianRandomGenerator(seed);

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
    GaussianRandomGenerator first = new GaussianRandomGenerator(seed.clone());
    GaussianRandomGenerator second = new GaussianRandomGenerator(seed.clone());

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
    GaussianRandomGenerator generator = new GaussianRandomGenerator(null);

    double value = generator.nextDouble();

    assertTrue(Double.isFinite(value));
  }

  @Test
  void nextDouble_whenUnderlyingGeneratorMocked_delegatesToNextGaussian() {
    MersenneTwister mockedTwister = Mockito.mock(MersenneTwister.class);
    Mockito.when(mockedTwister.nextGaussian()).thenReturn(0.5);

    GaussianRandomGenerator generator = new GaussianRandomGenerator(0);
    generator.generator = mockedTwister;

    double value = generator.nextDouble();

    assertEquals(0.5, value, 0.0);
    Mockito.verify(mockedTwister).nextGaussian();
  }
}
