# IOC Normalization

This project seeks to take in IOCs from various threat intel feeds, normalize them into a common format, then output CSV files by IOC type (dns, url, ip, file hash, email, ssl hash) in addition to outputting a format specific to Loki (https://github.com/Neo23x0/Loki).

## Quick Start
- folder structure needs to be as follows
- [top level directory]
    - alienvault
    - mandiant
    - crowdstrike
    - threatfox
    - custom
    - old
- the IOC CSV files need to be in each directory according to their source
- the custom folder is for CSVs exported from Google Sheets that have the following header
    - `Indicator,Type,Updated,Attribution,Source`
    - Type field follows the same naming convention as AlienVault
        - domain
        - IPv4
        - email
        - URL
        - FileHash-MD5
        - FileHash-SHA1
        - FileHash-SHA256
        - hostname
- the old folder is for IOCs that have already been processed by type: ip_all.csv, dns_all.csv, etc

## Example Usage
- `ioc_normalization.py -p /top_level_directory [-o /output/directory]`

## Notes
- because Alienvault IOCs usually don't have very good descriptions, you must name the files with the relevant context and date in this format: "[context]_[source]_YYYY-MM-DD.csv"
    - example: qakbot_att_2021-01-01.csv
``` 
“I didn't have time to write a short letter, so I wrote a long one instead.”

― Mark Twain 
```

## Future Works
- add argument for active web pull for tor exit node IPs and SSL hash blacklists
- transition ThreatFox to web pull also
- add error checking
- merging of old output needs testing