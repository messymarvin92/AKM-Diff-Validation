# SSID AKM Checker

`ssid_akm_checker.py` is a Python command-line tool that analyzes IEEE
802.11 packet captures and reports SSIDs observed with different
advertised Authentication and Key Management (AKM) suite sets.

It uses Scapy to read PCAP/PCAPNG captures, inspect wireless beacon
frames, extract SSIDs and AKM suites from information elements, and
compare the results across BSSIDs. Probe response frames can optionally
be included.

## Why this tool?

Multiple access points may advertise the same SSID while advertising
different authentication options. This can be intentional, for example,
during a security migration or it may indicate a configuration
inconsistency that needs investigation.

SSID AKM Checker helps identify these differences from packet captures.
A mismatch is evidence of differing advertised security configuration;
it does not, by itself, prove the cause of a client connectivity or
roaming issue.

## Features

-   Analyzes `.pcap`, `.pcapng`, and `.cap` files.
-   Accepts a single capture file or a directory of captures.
-   Supports recursive directory scanning.
-   Analyzes beacon frames by default.
-   Optionally analyzes probe response frames.
-   Extracts SSIDs and BSSIDs and parses advertised RSN AKM suite
    selectors.
-   Recognizes WPA vendor-specific AKM information.
-   Normalizes AKM suite sets so ordering differences do not create
    false positives.
-   Reports SSIDs observed with multiple distinct AKM suite sets.
-   Optionally excludes open networks with no advertised AKM.
-   Prints associated BSSIDs, beacon counts, and capture filenames.
-   Optionally exports findings to CSV.

## Requirements

-   Python 3
-   Scapy

Install Scapy:

``` bash
python3 -m pip install scapy
```

The script does not require Wireshark or `tshark`.

## Usage

### Analyze one capture file

``` bash
python3 ssid_akm_checker.py capture.pcap
```

### Analyze a directory

``` bash
python3 ssid_akm_checker.py /path/to/pcaps/
```

By default, the script processes capture files directly inside the
specified directory.

### Search directories recursively

``` bash
python3 ssid_akm_checker.py /path/to/pcaps/ -r
```

### Include probe responses

``` bash
python3 ssid_akm_checker.py /path/to/pcaps/ -r --include-probe-resp
```

Beacon frames are always analyzed. This option adds probe response
frames to the analysis.

### Exclude open networks and export CSV

``` bash
python3 ssid_akm_checker.py capture.pcapng --exclude-open --csv results.csv
```

### Display help

``` bash
python3 ssid_akm_checker.py --help
```

## Command-line options

  -----------------------------------------------------------------------
  Argument                            Description
  ----------------------------------- -----------------------------------
  `path`                              Required path to a supported
                                      capture file or a directory
                                      containing capture files.

  `-h`, `--help`                      Display the help message and exit.

  `-r`, `--recursive`                 Recurse into subdirectories when
                                      processing a directory.

  `--include-probe-resp`              Analyze probe response frames as
                                      well as beacon frames.

  `--exclude-open`                    Ignore observations with no
                                      advertised AKM suite.

  `--csv FILE`                        Write findings to the specified CSV
                                      file as well as printing them.
  -----------------------------------------------------------------------

Supported file extensions are `.pcap`, `.pcapng`, and `.cap`.

## How it works

1.  **Discover capture files.** The script accepts a file or directory
    and can optionally search directories recursively.
2.  **Read management frames.** It uses Scapy's packet reader to inspect
    beacon frames and, optionally, probe response frames.
3.  **Extract SSID and AKM data.** It parses tagged information
    elements, including the SSID element, RSN information element, and
    WPA vendor-specific information.
4.  **Normalize AKM suites.** Advertised suite values are stored as
    sets, so their order does not affect comparison.
5.  **Group observations by SSID.** Each observation is associated with
    its BSSID, source capture filename, and count.
6.  **Report differences.** An SSID is reported when more than one
    distinct AKM suite set was observed.

The script reporting distinct AKM suites.

```text
==============================================================================
SSIDs broadcast with DIFFERENT AKM suites: 1
==============================================================================

SSID: 'CorpWifi'  (2 different AKM sets)
  AKM: 802.1X
    BSSIDs (1): 9c:ef:d5:f6:30:65
    Beacons: 73   Files: hostapd_same_ssid_lab_setup_8021x_CorpWifi.pcapng
  AKM: PSK
    BSSIDs (1): 9c:ef:d5:f6:94:2e
    Beacons: 94   Files: hostapd_same_ssid_lab_setup_psk_CorpWifi.pcapng
```

The script skips hidden or null SSIDs. If no mismatches are found, it
prints:

``` text
No SSIDs found broadcasting different AKM suite sets.
```


## Understanding the output

For a reported SSID, the tool displays:

-   The SSID and number of distinct AKM suite sets observed.
-   Each AKM suite set.
-   The BSSIDs advertising that set.
-   The number of matching frames observed and the capture filenames.

A reported mismatch should be investigated in context. Differences may
be expected during a migration or may reflect a misconfigured access
point. The tool does not determine whether an access point is authorized
or rogue.

No reported mismatch means only that the analyzed frames did not show
multiple AKM suite sets for an SSID. It does not guarantee that every
access point in the WLAN was captured or that the WLAN is correctly
configured.

## CSV output

When `--csv FILE` is specified, the script writes the following columns:

  -----------------------------------------------------------------------
  Column                              Description
  ----------------------------------- -----------------------------------
  `SSID`                              SSID associated with the finding.

  `AKM_Suites`                        Formatted AKM suite set.

  `BSSIDs`                            Semicolon-separated BSSIDs
                                      associated with the suite set.

  `Beacon_Count`                      Number of matching frames counted
                                      by the script.

  `Files`                             Semicolon-separated capture
                                      filenames containing the
                                      observation.
  -----------------------------------------------------------------------

The script uses the `Beacon_Count` column name even when probe responses
are included.

## Suggested lab validation

### Test 1: Consistent AKM configuration

1.  Configure two lab access points to advertise the same SSID with
    matching AKM suite sets.
2.  Capture their beacon frames.
3.  Run the script against the directory containing the captures.
4.  Confirm that the SSID is not reported as having different AKM suite
    sets.

Example:

``` bash
python3 ssid_akm_checker.py same_ssid_same_akm/
```

### Test 2: Inconsistent AKM configuration

1.  Configure two lab access points to advertise the same SSID with
    different AKM suite sets.
2.  Capture their beacon frames.
3.  Run the script against the directory containing the captures.
4.  Confirm that the SSID and its distinct AKM suite sets are reported.

Example:

``` bash
python3 ssid_akm_checker.py different_akm/
```

Use a controlled lab environment and disposable test credentials.

## Limitations

-   The tool analyzes advertised management-frame information it does
    not perform client authentication or prove the root cause of a
    connectivity issue.
-   Results depend on capture coverage and the frames present in the
    supplied files.
-   Different AKM suites may be intentional and should be reviewed
    against the WLAN's design and security policy.
-   Hidden or null SSIDs are skipped.
-   The output is intended to support investigation, not replace
    validation of the access point configuration.

## Responsible use

Capture and analyze wireless traffic only in environments where you have
authorization. Protect packet captures and exported reports because they
may reveal information about your wireless environment.

## License

No license is specified by this repository. Add a `LICENSE` file if you
want to define how others may use, modify, and redistribute the project.
