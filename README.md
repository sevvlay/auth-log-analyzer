# Auth Log Brute-Force Detector

A Python script designed to analyze SSH `auth.log` files and automatically detect brute-force attack patterns.

This tool simulates a basic SIEM (Security Information and Event Management) detection rule by identifying high-frequency failed login attempts from specific IP addresses within a defined time window.

## How It Works

1.  The script reads the `auth.log` file line by line.
2.  It uses Regex to filter for "Failed password" lines and extract the exact timestamp and IP address.
3.  All failed attempts are grouped by their source IP address.
4.  Finally, it analyzes each IP's attempt history to see if the number of attempts (`ATTEMPT_THRESHOLD`) occurred faster than the allowed time limit (`TIME_WINDOW_MINUTES`).
5.  If an attack pattern is matched, a clear alert is printed to the console.

## Dataset

The included `auth.log` file is a sample dataset containing realistic SSH authentication logs. It includes a high-volume, automated brute-force attack originating from a single IP, which this script is designed to catch.

## Core Libraries Used

This script uses **only** standard Python libraries (no external packages needed):

* **`re` (Regex):** Used to parse the complex log lines and accurately extract data.
* **`collections.defaultdict`:** Used to efficiently create and manage the list of timestamps for each unique IP address.
* **`datetime`:** Used to convert the log timestamps into objects that allow for mathematical comparison (i.e., calculating the time difference between attacks).

## Usage

Place your `auth.log` file in the same directory as the script and run:

```bash
python analysis.py
