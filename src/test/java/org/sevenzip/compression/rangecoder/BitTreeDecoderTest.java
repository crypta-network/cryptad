package org.sevenzip.compression.rangecoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BitTreeDecoderTest {

  @Mock private Decoder rangeDecoder;

  private BitTreeDecoder decoder;

  @BeforeEach
  void setUp() {
    decoder = new BitTreeDecoder(3);
    decoder.init();
  }

  @Test
  void init_setsModelsToInitialProbabilities() throws Exception {
    short[] models = extractModels(decoder);

    for (short model : models) {
      assertEquals((short) (Decoder.BIT_MODEL_TOTAL >>> 1), model);
    }
  }

  @Test
  void decode_whenBitsProduceValue_returnsExpectedSymbol() throws Exception {
    when(rangeDecoder.decodeBit(any(short[].class), anyInt())).thenReturn(1, 0, 1);

    int result = decoder.decode(rangeDecoder);

    assertEquals(5, result);
    ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(rangeDecoder, org.mockito.Mockito.times(3))
        .decodeBit(any(short[].class), indexCaptor.capture());
    assertEquals(1, indexCaptor.getAllValues().get(0));
    assertEquals(3, indexCaptor.getAllValues().get(1));
    assertEquals(6, indexCaptor.getAllValues().get(2));
  }

  @Test
  void reverseDecode_whenBitsProduceValue_returnsExpectedSymbol() throws Exception {
    when(rangeDecoder.decodeBit(any(short[].class), anyInt())).thenReturn(1, 0, 1);

    int result = decoder.reverseDecode(rangeDecoder);

    assertEquals(5, result);
    ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(rangeDecoder, org.mockito.Mockito.times(3))
        .decodeBit(any(short[].class), indexCaptor.capture());
    assertEquals(1, indexCaptor.getAllValues().get(0));
    assertEquals(3, indexCaptor.getAllValues().get(1));
    assertEquals(6, indexCaptor.getAllValues().get(2));
  }

  @Test
  void staticReverseDecode_withStartIndex_offsetsModelLookup() throws Exception {
    when(rangeDecoder.decodeBit(any(short[].class), anyInt())).thenReturn(1, 1);
    short[] models = new short[10];

    int result = BitTreeDecoder.reverseDecode(models, 5, rangeDecoder, 2);

    assertEquals(3, result);
    ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(rangeDecoder, org.mockito.Mockito.times(2))
        .decodeBit(any(short[].class), indexCaptor.capture());
    assertEquals(6, indexCaptor.getAllValues().get(0));
    assertEquals(8, indexCaptor.getAllValues().get(1));
  }

  @Test
  void decode_whenDecoderThrows_propagatesIOException() throws Exception {
    when(rangeDecoder.decodeBit(any(short[].class), anyInt())).thenThrow(new IOException("boom"));

    assertThrows(IOException.class, () -> decoder.decode(rangeDecoder));
  }

  private short[] extractModels(BitTreeDecoder target) throws Exception {
    Field modelsField = BitTreeDecoder.class.getDeclaredField("models");
    modelsField.setAccessible(true);
    return (short[]) modelsField.get(target);
  }
}
