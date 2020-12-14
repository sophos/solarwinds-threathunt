# Useful Splunk Searches for hunting Solarwinds

### Search for Event code 4624 (any logins to the Solarwinds server), find out who's credentials might be compromised. 
`search index=oswinsec solarwinds* "EventCode=4624" Workstation_Name="solarwinds*"
| stats count min(_time) AS first_time max(_time) AS last_time by Workstation_Name Security_ID Logon_Type 
| convert timeformat="%d/%m/%Y %H:%M:%S" ctime(*_time)
| sort count`

### Check Bro for any Solarwinds DNS lookups, find any unknown or test instances
search index=bro sourcetype=bro_dns query="solarwinds.com"
| rex field=_raw "(^\d+\.\d+\s\S+\s)(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip IN ("solarwinds_ip","solarwinds_ip","solarwinds_ip","solarwinds_ip")
