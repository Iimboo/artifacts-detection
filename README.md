# README

## Python Script for Detecting Changes in Windows Artifacts

This Python script is designed to detect changes in Windows artifacts, such as logs. This functionality is crucial due to the overreliance on third-party applications that are often limited to the general public. By analyzing Windows artifacts, we aim to determine their reliability, consistency, and potential vulnerabilities.

## Features

- **Integrated Tools**: Utilizes multiple tools such as Procmon, Tracerpt, WinPrefetchView, and FullEventLogView, providing an all-in-one solution for detecting changes in Windows artifacts.
- **Real-Time Monitoring**: Detects changes in artifacts while the script runs and upon stopping.
- **Filtering Option**: Allows filtering by process name, enabling focused analysis on specific processes.
- **Output Generation**: Generates multiple output files in the "output" folder, providing detailed information on the detected changes.

## How It Works

1. **Initial Setup**:
   - The script must be run with administrator privileges.
   - It will clear all existing event logs before starting the monitoring process.
   
2. **First Scan**:
   - Scans the system to collect initial data on EVTX and ETL logs.
   - Records the number of logs in each EVTX file and prepares lists of ETL files and prefetch files.
   - Disables and re-enables the logs to start with a clean slate.

3. **Testing Phase**:
   - Procmon starts to capture system activities.
   - Users perform their tasks, and once completed, Procmon must be closed manually to avoid log corruption.

4. **Second Scan**:
   - Compares the current state of the system with the initial scan.
   - Records changes in prefetch files, EVTX logs, and ETL logs.

5. **Output Files**:
   - **Etl_changes.txt**: Lists significant ETL log changes.
   - **Evtx_changes.txt**: Lists significant EVTX log changes.
   - **FileChanges1.csv**: Shows changes made to files by processes or the filtered process.
   - **Prefetch_changes.txt**: Lists new or modified prefetch files.
   - Detailed CSVs for each EVTX and ETL log change, e.g., `Security.evtx.csv`.

6. **Optional Filtering**:
   - Provides an option to filter logs by process name, generating focused output files.

7. **Re-enabling Logs**:
   - Ensures all logs are re-enabled after the analysis to maintain system functionality.

## Output Files

- **Etl_changes.txt**: Detects significant ETL log changes.
- **Evtx_changes.txt**: Detects significant EVTX log changes.
- **FileChanges1.csv**: Shows changes made to files by processes or the filtered process.
- **Prefetch_changes.txt**: Detects changes in prefetch files.
- **Detailed Log CSVs**: For important ETL and EVTX log changes, respective CSVs are generated detailing the actions taken. For example, `Security.evtx` changes are listed in `Evtx_changes.txt`, and a corresponding CSV, `Security.evtx.csv`, is generated listing all related log actions (excluding noise).
