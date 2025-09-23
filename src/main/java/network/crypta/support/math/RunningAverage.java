package network.crypta.support.math;

import java.io.Serializable;

/**
 * A running average. That is, something that takes reports as numbers and generates a current
 * value. Synchronized class, including clone().
 */
public interface RunningAverage extends Serializable {

  /**
   * Copy the RunningAverage (create a snapshot). Deep copy, the new RA won't change when the first
   * one does. Will synchronize on the original during the copy process.
   */
  RunningAverage clone();

  /**
   * @return
   */
  double currentValue();

  /**
   * @param d
   */
  void report(double d);

  /**
   * @param d
   */
  void report(long d);

  /**
   * Get what currentValue() would be if we reported some given value
   *
   * @param r the value to mimic reporting
   * @return the output of currentValue() if we were to report r
   */
  double valueIfReported(double r);

  /**
   * @return the total number of reports on this RunningAverage so far. Used for weighted averages,
   *     confidence/newbieness estimation etc.
   */
  long countReports();
}
