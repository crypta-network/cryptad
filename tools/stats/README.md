Stats Probe Utilities

Purpose
- Auxiliary scripts and a small Java probe used to measure network size and churn by probing a local Crypta node and publishing summarized results.

What It Does
- Probing: `probe_test/ProbeTester.java` generates randomized probe locations and sends commands via `telnet localhost 2323` to a running node.
- Summarization: `probe_test/summarize.sh` parses console output (e.g., "Completed", "Probe trace:"), extracts peer IDs, and computes metrics for a single sample and rolling windows (last 5 and last 24 samples). It produces a `full_data` data file.
- Visualization: `probe_test/plot.gnu` and `plot_activelink.gnu` generate `network_size.png`, `churn.png`, and a small `activelink.png` from the aggregated data.
- Publishing: `probe_test/upload.sh`, `upload_fcp.sh`, and `upload_usk.sh` upload graphs and data over FCP (netcat to `localhost:9481`). `index.xhtml` is templated with the timestamp to link artifacts.
- Scheduling: `probe_test/schedule.sh` suggests running every 5 hours to spread sampling across times of day.

Requirements
- Running Crypta node with console available on `localhost:2323` and FCP on `localhost:9481`.
- Tools: `bash`, `telnet`, `nc` (netcat), `sed`, `join`, `gnuplot`.
- Java to compile and run `ProbeTester.java` (e.g., `javac ProbeTester.java && java ProbeTester ...`).
- Configure upload keys/paths in `upload_fcp.sh` and `upload_usk.sh` (placeholders are present).

Usage (example)
1) Start a node locally with console and FCP enabled.
2) In `tools/stats/probe_test`, compile `ProbeTester.java` if needed:
   - `javac MersenneTwister.java ProbeTester.java`
3) Run a probe batch (e.g., 120 probes per process):
   - `./probe_test.sh 120`
4) Summaries and graphs are written under `results/<UTC_TIMESTAMP>/`.
5) Optional: upload results with `./upload.sh <UTC_TIMESTAMP>` after setting keys.

Notes
- This is optional tooling for monitoring and research; it is not part of the daemon build/runtime.
- Probing and uploads can create load on your node and network; use responsibly and adjust frequency as needed.
