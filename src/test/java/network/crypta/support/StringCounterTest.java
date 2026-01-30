package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Allow method names in the given_when_then style
class StringCounterTest {

  @Test
  void get_whenMissing_thenZero() {
    // Arrange
    StringCounter sc = new StringCounter();

    // Act & Assert
    assertEquals(0, sc.get("missing"));
  }

  @Test
  void inc_whenNewKey_thenCountIsOne() {
    // Arrange
    StringCounter sc = new StringCounter();

    // Act
    sc.inc("alpha");

    // Assert
    assertEquals(1, sc.get("alpha"));
  }

  @Test
  void inc_whenCalledMultipleTimes_thenAccumulatesPerKey() {
    // Arrange
    StringCounter sc = new StringCounter();

    // Act
    sc.inc("alpha");
    sc.inc("beta");
    sc.inc("alpha");
    sc.inc("alpha");

    // Assert
    assertEquals(3, sc.get("alpha"));
    assertEquals(1, sc.get("beta"));
  }

  @Test
  void toLongString_whenEmpty_returnsEmptyString() {
    // Arrange
    StringCounter sc = new StringCounter();

    // Act
    String s = sc.toLongString();

    // Assert
    assertEquals("", s);
  }

  @Test
  void toLongString_whenOnlyNullKey_formatsLiteralNullAndCount() {
    // Arrange
    StringCounter sc = new StringCounter();
    sc.inc(null);

    // Act
    String s = sc.toLongString();

    // Assert
    // StringBuilder appends null as literal "null"; verify formatting and no trailing newline
    assertEquals("null\t1", s);
  }

  @Test
  void toLongString_whenMultipleEntries_ordersByCountDesc_andReverseAlphaOnTies() {
    // Arrange
    StringCounter sc = new StringCounter();
    sc.inc("a");
    sc.inc("b");
    sc.inc("c");
    sc.inc("a");
    sc.inc("b");
    // Now: a=2, b=2, c=1. For ties the implementation reverses alpha when sorting descending

    // Act
    String s = sc.toLongString();

    // Assert
    String expected =
        """
        b	2
        a	2
        c	1
        """
            .stripTrailing();
    assertEquals(expected, s);
  }

  @Test
  void toTableRows_whenNoItems_returnsZeroAndAddsNoRows() {
    // Arrange
    StringCounter sc = new StringCounter();
    HTMLNode table = new HTMLNode("table");

    // Act
    int rows = sc.toTableRows(table);

    // Assert
    assertEquals(0, rows);
    assertEquals(0, table.getChildren().size());
  }

  @Test
  void toTableRows_whenItems_addsRowsAndCellsInDescendingOrder() {
    // Arrange
    StringCounter sc = new StringCounter();
    sc.inc("a");
    sc.inc("b");
    sc.inc("c");
    sc.inc("a");
    sc.inc("b");
    HTMLNode table = new HTMLNode("table");

    // Act
    int rows = sc.toTableRows(table);

    // Assert
    assertEquals(3, rows);
    assertEquals(3, table.getChildren().size());

    // Row order should be: b(2), a(2), c(1)
    assertRow(table.getChildren().get(0), 2, "b");
    assertRow(table.getChildren().get(1), 2, "a");
    assertRow(table.getChildren().get(2), 1, "c");
  }

  @Test
  void toLongString_whenNullAndEqualCount_throwsNullPointerException() {
    // Arrange: mix a null key with a non-null with equal count
    StringCounter sc = new StringCounter();
    sc.inc(null);
    sc.inc("x");

    // Act & Assert: comparator dereferences null during tie-break on string
    assertThrows(NullPointerException.class, sc::toLongString);
  }

  @Test
  void toTableRows_whenNullAndEqualCount_throwsNullPointerException() {
    // Arrange
    StringCounter sc = new StringCounter();
    sc.inc(null);
    sc.inc("x");
    HTMLNode table = new HTMLNode("table");

    // Act & Assert: sorting happens before row creation and triggers NPE
    assertThrows(NullPointerException.class, () -> sc.toTableRows(table));
  }

  private static void assertRow(HTMLNode row, int count, String text) {
    // Row should be a <tr> with two <td> children
    assertEquals("tr", row.getName());
    assertEquals(2, row.getChildren().size());

    HTMLNode c0 = row.getChildren().get(0);
    HTMLNode c1 = row.getChildren().get(1);
    assertEquals("td", c0.getName());
    assertEquals("td", c1.getName());

    // Expect the first cell text to end with a non-breaking space entity.
    assertEquals(count + "&nbsp;", c0.generateChildren());
    assertEquals(text, c1.generateChildren());
  }
}
