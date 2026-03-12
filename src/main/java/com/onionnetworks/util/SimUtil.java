package com.onionnetworks.util;

import java.util.Arrays;
import java.util.StringJoiner;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Miscellaneous simulation utilities used by the legacy Onion Networks tooling. The helper methods
 * focus on printing small shell scripts for the GNU Plotutils {@code graph} command and on simple
 * numeric helpers needed by those scripts. This class provides only static helpers and cannot be
 * instantiated.
 *
 * <p>Typical usage is to call {@link #printGraphCommand(String, String, String, int[][], String[])}
 * to emit a ready-to-run script to standard output, redirect that output to a file, and execute the
 * file to visualize multiple plots. The median and swap helpers exist to support lightweight data
 * massaging in the same code paths without pulling in additional dependencies.
 *
 * <p>The utilities are intentionally minimal and have no internal synchronization; callers must
 * handle any required threading guarantees. Methods mutate the arrays that are passed in, so
 * callers should supply defensive copies when necessary to preserve original inputs.
 */
public final class SimUtil {

  private static final Logger LOGGER = Logger.getLogger(SimUtil.class.getName());

  private SimUtil() {
    throw new IllegalStateException("Utility class");
  }

  /**
   * Prints a shell script that feeds plot data to the Plotutils {@code graph} command. The script
   * is written to standard output so callers can redirect it to a temporary file and execute it
   * with a chosen output type. Each dataset in {@code plots} becomes one series; datasets are
   * delimited by a blank line as expected by {@code graph}.
   *
   * @param title graph title text; used verbatim in the {@code -L} flag, may be empty but not null.
   * @param x label for the X axis; supplied to {@code -X}, should describe units or scale.
   * @param y label for the Y axis; supplied to {@code -Y}, should describe units or scale.
   * @param plots two-dimensional array of series values; outer dimension selects the series, inner
   *     elements are emitted as space-separated integers per line.
   * @param graphNames optional descriptive names for debug logging; not used in the generated
   *     script, can be {@code null} when not needed.
   */
  @SuppressWarnings("java:S106")
  public static void printGraphCommand(
      String title, String x, String y, int[][] plots, String[] graphNames) {
    String script = buildGraphCommandScript(title, x, y, plots);
    System.out.print(script);
    System.out.flush();
    if (graphNames != null && LOGGER.isLoggable(Level.FINE)) {
      LOGGER.log(Level.FINE, () -> "Graph names: " + Arrays.toString(graphNames));
    }
  }

  private static String buildGraphCommandScript(String title, String x, String y, int[][] plots) {
    StringBuilder builder = new StringBuilder();
    builder
        .append("#!/bin/sh")
        .append(System.lineSeparator())
        .append("# By default (no args) it will display it in X, use $1=gif,png,for images")
        .append(System.lineSeparator())
        .append("if [ -n \"$1\" ]")
        .append(System.lineSeparator())
        .append("then type=$1")
        .append(System.lineSeparator())
        .append("else type=\"X\"")
        .append(System.lineSeparator())
        .append("fi")
        .append(System.lineSeparator())
        .append("echo \"");
    for (int[] plot : plots) {
      for (int value : plot) {
        builder.append(value).append(' ');
      }
      builder.append(System.lineSeparator()).append(System.lineSeparator());
    }
    builder.append("\" | graph -W .003 -C -T $type -L \"").append(title).append("\" -X \"");
    builder.append(x).append("\" -Y \"").append(y).append('"');
    return builder.toString();
  }

  /**
   * Sorts the provided array in place using a simple bubble sort and returns the median element.
   * The method logs the sorted contents at {@link Level#INFO} to aid debugging. Input arrays are
   * expected to be non-empty; callers that require the lower median for even-length arrays must
   * adjust after the call.
   *
   * @param data integer array to sort and examine; contents are reordered, not copied, and must be
   *     non-null with at least one element.
   * @return the element at {@code data.length / 2} after sorting; for even lengths this is the
   *     upper middle value.
   */
  public static int getMedian(int[] data) {
    // do a stupid bubble sort then pick middle.
    // FIX, this sort doesn't have to suck.
    for (int i = 0; i < data.length - 1; i++) {
      for (int j = i + 1; j < data.length; j++) {
        if (data[i] > data[j]) {
          swap(data, i, j);
        }
      }
    }
    LOGGER.log(Level.INFO, () -> joinValuesWithTrailingSpace(data));
    return data[data.length / 2];
  }

  private static String joinValuesWithTrailingSpace(int[] data) {
    StringJoiner joiner = new StringJoiner(" ", "", " ");
    for (int value : data) {
      joiner.add(Integer.toString(value));
    }
    return joiner.toString();
  }

  /**
   * Exchanges two elements within the provided integer array. The operation is performed in place
   * and is commonly used by the bubble sort inside {@link #getMedian(int[])} to reorder values.
   *
   * @param data target array whose elements will be swapped; must be non-null and large enough to
   *     contain both indices.
   * @param posA zero-based index of the first element to exchange; must satisfy {@code 0 <= posA <
   *     data.length}.
   * @param posB zero-based index of the second element to exchange; must satisfy {@code 0 <= posB <
   *     data.length}.
   */
  public static void swap(int[] data, int posA, int posB) {
    int tmp = data[posA];
    data[posA] = data[posB];
    data[posB] = tmp;
  }
}
