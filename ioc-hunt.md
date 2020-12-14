# Live Discover threathunt for Solarwinds

The query takes a CSV file published by SOPHOS Security based on Fireeye published IOCs and parses out the IOCs, then performs a hunt. Note you have to setup the variables and use the RAW csv file in Sophos Central.

Add the query below to your Sophos Central Instance and then setup a Central variable as detailed in the section below. 

https://github.com/sophos-cybersecurity/solarwinds-threathunt/blob/master/query-for-central.sql

## Variables in Central

|Detail |Type  | 	Value  |   
|---|---|---|
| Number of Hours of activity to search  | STRING | 24 |  
|  RAW IOC List location from a URL|STRING|https://raw.githubusercontent.com/sophos-cybersecurity/solarwinds-threathunt/master/iocs.csv | 
|Start Search From | DATE | 12/12/2020 12:00:00 |

## Testing

If you drop an executable in the C:\PerfLogs\ directory and run the query it should show up as a MATCH for one of the IOC's. If that isn't working as expected you may want to check that CURL can reach the remote IOC list specified in the variable above.

## Toubleshooting

To check that CURL is returning results run the query below

```
SELECT * FROM curl WHERE url = 'https://raw.githubusercontent.com/sophos-cybersecurity/solarwinds-threathunt/master/iocs.csv'
```

The query above should return a single row with a 200 for response and a large data blob in the 'results' column. If this isn't working as epxected and the device can reach the internet something else may be preventing the osquery service from being able to reach the remote site.  It may be a problem at the ISP, GIT, firewall rules, something in-line identifying the content of the CSV as MAL etc.

## Raw IOCs (work in progress)

https://raw.githubusercontent.com/sophos-cybersecurity/solarwinds-threathunt/master/iocs.csv

