# Auth Log Brute-Force Detector

A Python script that analyzes SSH `auth.log` files to detect brute-force attacks.

This tool simulates a basic SIEM detection rule. It's part of my security automation portfolio to demonstrate skills in log analysis, threat detection, and Python scripting.

## Features

* Parses timestamps and IP addresses from logs using Regex.
* Uses a sliding window algorithm to detect high-frequency failed logins.
* Configurable alert threshold (e.g., 10 attempts in 5 minutes).

## Usage

Place your `auth.log` file in the same directory as the script and run:

```bash
python analysis.py
