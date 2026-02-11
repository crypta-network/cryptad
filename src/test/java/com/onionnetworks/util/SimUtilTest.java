package com.onionnetworks.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class SimUtilTest {

  private Logger logger;
  private Handler handler;
  private PrintStream originalOut;
  private ByteArrayOutputStream stdout;
  private Level previousLevel;
  private boolean previousUseParentHandlers;

  @BeforeEach
  void setUpLogger() {
    logger = Logger.getLogger(SimUtil.class.getName());
    previousUseParentHandlers = logger.getUseParentHandlers();
    previousLevel = logger.getLevel();
    logger.setUseParentHandlers(false);
    logger.setLevel(Level.ALL);
    TestLogHandler testHandler = new TestLogHandler();
    logger.addHandler(testHandler);
    handler = testHandler;

    originalOut = System.out;
    stdout = new ByteArrayOutputStream();
    System.setOut(new PrintStream(stdout, false, StandardCharsets.UTF_8));
  }

  @AfterEach
  void tearDownLogger() {
    logger.removeHandler(handler);
    logger.setUseParentHandlers(previousUseParentHandlers);
    logger.setLevel(previousLevel);
    System.setOut(originalOut);
  }

  @Test
  void printGraphCommand_whenCalled_outputsExpectedScript() {
    int[][] plots = {
      {1, 2},
      {3, 4}
    };
    String[] names = {"first", "second"};

    SimUtil.printGraphCommand("Title", "X Axis", "Y Axis", plots, names);

    String ls = System.lineSeparator();
    String expected =
        "#!/bin/sh"
            + ls
            + "# By default (no args) it will display it in X, use $1=gif,png,for images"
            + ls
            + "if [ -n \"$1\" ]"
            + ls
            + "then type=$1"
            + ls
            + "else type=\"X\""
            + ls
            + "fi"
            + ls
            + "echo \""
            + "1 2 "
            + ls
            + ls
            + "3 4 "
            + ls
            + ls
            + "\" | graph -W .003 -C -T $type -L \"Title\" -X \"X Axis\" -Y \"Y Axis\"";

    assertEquals(expected, stdout.toString(StandardCharsets.UTF_8));
  }

  @Test
  void getMedian_whenUnsortedOddLength_returnsMedianAndSortsArray() {
    int[] data = {5, 1, 3};

    int median = SimUtil.getMedian(data);

    assertEquals(3, median);
    assertArrayEquals(new int[] {1, 3, 5}, data);
    assertEquals("1 3 5 ", firstLogMessage());
  }

  @Test
  void getMedian_whenEvenLength_returnsUpperMiddleValue() {
    int[] data = {4, 1, 2, 3};

    int median = SimUtil.getMedian(data);

    assertEquals(3, median);
    assertArrayEquals(new int[] {1, 2, 3, 4}, data);
  }

  @Test
  void getMedian_whenEmptyArray_throwsArrayIndexOutOfBoundsException() {
    int[] data = new int[0];

    assertThrows(ArrayIndexOutOfBoundsException.class, () -> SimUtil.getMedian(data));
  }

  @Test
  void swap_whenIndicesProvided_swapsValues() {
    int[] data = {10, 20, 30};

    SimUtil.swap(data, 0, 2);

    assertArrayEquals(new int[] {30, 20, 10}, data);
  }

  private String firstLogMessage() {
    return ((TestLogHandler) handler).records.getFirst().getMessage();
  }

  private static final class TestLogHandler extends Handler {

    private final List<LogRecord> records = new ArrayList<>();

    @Override
    public void publish(LogRecord logRecord) {
      records.add(logRecord);
    }

    @Override
    public void flush() {
      // No-op: in-memory log collection requires no flushing.
    }

    @Override
    public void close() {
      // No-op: nothing external to release in test handler.
    }
  }
}
