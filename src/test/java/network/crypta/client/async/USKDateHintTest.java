package network.crypta.client.async;

import static network.crypta.client.async.USKDateHint.Type.DAY;
import static network.crypta.client.async.USKDateHint.Type.MONTH;
import static network.crypta.client.async.USKDateHint.Type.WEEK;
import static network.crypta.client.async.USKDateHint.Type.YEAR;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.time.LocalDate;
import org.junit.jupiter.api.Test;

public class USKDateHintTest {

  @Test
  public void getYear() {
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    assertEquals(hint.get(YEAR), "2023");
  }

  @Test
  public void getMonth() {
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    assertEquals(hint.get(MONTH), "2023-5");
  }

  @Test
  public void getDay() {
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    assertEquals(hint.get(DAY), "2023-5-1");
  }

  @Test
  public void getWeek() {
    USKDateHint hintStartOfYear = new USKDateHint(LocalDate.parse("2023-01-01"));
    USKDateHint hintEndOfYear = new USKDateHint(LocalDate.parse("2023-12-31"));
    assertEquals(hintStartOfYear.get(WEEK), "2023-WEEK-1");
    assertEquals(hintEndOfYear.get(WEEK), "2024-WEEK-1");
  }

  @Test
  public void getData() {
    USKDateHint hint = new USKDateHint(LocalDate.parse("2023-06-01"));
    assertEquals(hint.getData(12345), "HINT\n12345\n2023-5-1\n");
  }
}
