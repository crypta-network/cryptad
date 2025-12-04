package org.sevenzip.compression.rangecoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class BitTreeEncoderTest {

  private static final int HALF_PROB = Encoder.BIT_MODEL_TOTAL >>> 1;

  @Test
  void encode_whenSymbolTraversesZeroBits_expectMsbOrderIndices() throws IOException {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    encoder.init();
    Encoder rangeEncoder = mock(Encoder.class);

    encoder.encode(rangeEncoder, 0);

    ArgumentCaptor<short[]> modelsCaptor = ArgumentCaptor.forClass(short[].class);
    ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> bitCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(rangeEncoder, times(3))
        .encode(modelsCaptor.capture(), indexCaptor.capture(), bitCaptor.capture());
    verifyNoMoreInteractions(rangeEncoder);

    List<short[]> modelsAcrossCalls = modelsCaptor.getAllValues();
    assertEquals(3, modelsAcrossCalls.size());
    assertSame(modelsAcrossCalls.get(0), modelsAcrossCalls.get(1));
    assertSame(modelsAcrossCalls.get(1), modelsAcrossCalls.get(2));
    assertEquals(List.of(1, 2, 4), indexCaptor.getAllValues());
    assertEquals(List.of(0, 0, 0), bitCaptor.getAllValues());
  }

  @Test
  void encode_whenSymbolAllOnes_expectMsbOrderIndices() throws IOException {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    encoder.init();
    Encoder rangeEncoder = mock(Encoder.class);

    encoder.encode(rangeEncoder, 7);

    InOrder order = inOrder(rangeEncoder);
    order.verify(rangeEncoder).encode(any(short[].class), eq(1), eq(1));
    order.verify(rangeEncoder).encode(any(short[].class), eq(3), eq(1));
    order.verify(rangeEncoder).encode(any(short[].class), eq(7), eq(1));
    verifyNoMoreInteractions(rangeEncoder);
  }

  @Test
  void reverseEncode_whenSymbolUsesLsbOrder_expectIndicesFollowLsbTraversal() throws IOException {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    encoder.init();
    Encoder rangeEncoder = mock(Encoder.class);

    encoder.reverseEncode(rangeEncoder, 0b110);

    InOrder order = inOrder(rangeEncoder);
    order.verify(rangeEncoder).encode(any(short[].class), eq(1), eq(0));
    order.verify(rangeEncoder).encode(any(short[].class), eq(2), eq(1));
    order.verify(rangeEncoder).encode(any(short[].class), eq(5), eq(1));
    verifyNoMoreInteractions(rangeEncoder);
  }

  @Test
  void getPrice_whenModelsInitialized_expectConstantPricePerBit() {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    encoder.init();

    int expectedPricePerBit = Encoder.getPrice(HALF_PROB, 0);
    int price = encoder.getPrice(0b101);

    assertEquals(expectedPricePerBit * 3, price);
  }

  @Test
  void getPrice_whenModelsDiffer_expectMsbPathSumsCorrespondingNodes() throws Exception {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    short[] models = getModels(encoder);
    models[1] = 300;
    models[3] = 700;
    models[6] = 1200;

    int price = encoder.getPrice(0b101);

    int expected =
        Encoder.getPrice(models[1], 1)
            + Encoder.getPrice(models[3], 0)
            + Encoder.getPrice(models[6], 1);
    assertEquals(expected, price);
  }

  @Test
  void reverseGetPrice_whenModelsDiffer_expectLsbPathSumsCorrespondingNodes() throws Exception {
    BitTreeEncoder encoder = new BitTreeEncoder(3);
    short[] models = getModels(encoder);
    models[1] = 250;
    models[2] = 600;
    models[5] = 1500;

    int price = encoder.reverseGetPrice(0b110);

    int expected =
        Encoder.getPrice(models[1], 0)
            + Encoder.getPrice(models[2], 1)
            + Encoder.getPrice(models[5], 1);
    assertEquals(expected, price);
  }

  @Test
  void reverseGetPrice_static_whenUsingExternalModels_expectStartIndexApplied() {
    short[] models = new short[16];
    Decoder.initBitModels(models);
    int startIndex = 2;
    int price = BitTreeEncoder.reverseGetPrice(models, startIndex, 3, 0b011);

    int expectedPricePerBit = Encoder.getPrice(HALF_PROB, 1);
    assertEquals(expectedPricePerBit * 3, price);
  }

  @Test
  void reverseEncode_static_whenUsingExternalModels_expectOffsetsApplied() throws IOException {
    short[] models = new short[16];
    Decoder.initBitModels(models);
    Encoder rangeEncoder = mock(Encoder.class);

    BitTreeEncoder.reverseEncode(models, 2, rangeEncoder, 3, 0b011);

    InOrder order = inOrder(rangeEncoder);
    order.verify(rangeEncoder).encode(models, 3, 1);
    order.verify(rangeEncoder).encode(models, 5, 1);
    order.verify(rangeEncoder).encode(models, 9, 0);
    verifyNoMoreInteractions(rangeEncoder);
  }

  private static short[] getModels(BitTreeEncoder encoder) throws Exception {
    Field field = BitTreeEncoder.class.getDeclaredField("models");
    field.setAccessible(true);
    return (short[]) field.get(encoder);
  }
}
