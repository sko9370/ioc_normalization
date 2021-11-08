# IOC Normalization

This project seeks to take in IOCs from various threat intel feeds, normalize them into a common format, then output CSV files by IOC type (dns, url, ip, file hash) in addition to outputting a format specific to Loki (https://github.com/Neo23x0/Loki).

## Example Usage
- `mandiant.py -p /directory/containing/csvs -o /output/directory`

## Notes
- because Alienvault IOCs don't have a column for any published/updated dates, you must create a directory with the date in the format of mm-dd-yyyy and store the IOCs retrieved from that day in that directory
- regex inside alienvault.py will use the name of the directory as the published/updated date to allow for tracking of approximately when the IOC was downloaded to track "staleness" of the IOC
- alienvault.py will expect a directory containing directories with dates containing CSVs
- CrowdStrike has a separate script that uses the pandas library because the original method of using the CSV standard library was slow and inefficient; however, both options should be kept as pandas does not come by default with python and some environments may have limited access to download pandas

## Future Works
- use a common date format for published and updated columns
- implement using pandas library as a commandline option
- deduplicate any IOCs
- implement API for Mandiant to pull directly instead of having to download CSVs manually from the web
- implement as a daily/weekly task to pull the most recent IOCs (last 30-60 days for example) to local storage so it's faster to copy over the IOCs
- experiment with Splunk KV stores for better lookup table efficiency
