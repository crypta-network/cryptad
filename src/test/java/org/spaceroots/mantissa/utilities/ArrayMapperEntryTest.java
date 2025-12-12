package org.spaceroots.mantissa.utilities;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ArrayMapperEntryTest {

  @Mock private ArraySliceMappable mappable;

  @Test
  void constructor_whenGivenObjectAndOffset_expectFieldsExposedUnmodified() {
    int offset = 5;

    ArrayMapperEntry entry = new ArrayMapperEntry(mappable, offset);

    assertSame(mappable, entry.object());
    assertEquals(offset, entry.offset());
  }

  @Test
  void constructor_whenObjectNull_expectNullStoredAndOffsetPreserved() {
    int offset = 0;

    ArrayMapperEntry entry = new ArrayMapperEntry(null, offset);

    assertNull(entry.object());
    assertEquals(offset, entry.offset());
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 1, -1, Integer.MAX_VALUE, Integer.MIN_VALUE})
  void constructor_whenOffsetBoundaryValues_expectExactValueStored(int offset) {
    ArrayMapperEntry entry = new ArrayMapperEntry(mappable, offset);

    assertEquals(offset, entry.offset());
  }
}
