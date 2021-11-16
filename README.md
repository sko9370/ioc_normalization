# IOC Normalization

This project seeks to take in IOCs from various threat intel feeds, normalize them into a common format, then output CSV files by IOC type (dns, url, ip, file hash) in addition to outputting a format specific to Loki (https://github.com/Neo23x0/Loki).

## Example Usage
- `ioc_normalization.py -p /directory/containing/csvs -o /output/directory`

## Notes
- because Alienvault IOCs usually don't have very good descriptions, you must name the files with the relevant context and date in this format: "[context]_YYYY-MM-DD.csv"
    - example: qakbot_2021-01-01.csv

## Future Works
- [Done] use a common date format for published and updated columns
- [Changed] implement using pandas library as a commandline option
    - use Pandas all the time, it's much more efficient
- [Done] deduplicate any IOCs
- implement API for Mandiant to pull directly instead of having to download CSVs manually from the web
- implement as a daily/weekly task to pull the most recent IOCs (last 30-60 days for example) to local storage so it's faster to copy over the IOCs
- experiment with Splunk KV stores for better lookup table efficiency
