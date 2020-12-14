# Useful Splunk Searches for hunting Solarwinds

### Search for Event code 4624 (any logins to the Solarwinds server) - find out credentials that could be compromised. 
`search index=oswinsec solarwinds* "EventCode=4624" Workstation_Name="solarwinds*"
| stats count min(_time) AS first_time max(_time) AS last_time by Workstation_Name Security_ID Logon_Type 
| convert timeformat="%d/%m/%Y %H:%M:%S" ctime(*_time)
| sort count`

### Check Bro for any Solarwinds DNS lookups -  find any unknown or test instances of Solarwinds
`search index=bro sourcetype=bro_dns query="solarwinds.com"
| rex field=_raw "(^\d+\.\d+\s\S+\s)(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip IN ("solarwinds_ip","solarwinds_ip","solarwinds_ip","solarwinds_ip")`


## Check for any historical HTTP/S traffic outbound to published IOCs with any applicable http/s logs
`search index=* index!=bro index!=appwebext deftsecurity.com OR freescanonline.com OR thedoccloud.com OR thedoccloud.com OR websitetheme.com OR highdatabase.com OR incomeupdate.com OR databasegalore.com OR panhardware.com OR zupertech.com OR appsync-api.eu-west-1.avsvmcloud.com OR appsync-api.eu-west-1.avsvmcloud.com OR appsync-api.us-east-2.avsvmcloud.com OR appsync-api.us-west-2.avsvmcloud.com OR appsync-api.us-west-2.avsvmcloud.com OR appsync-api.eu-west-1.avsvmcloud.com | stats count earliest(_time) AS Earliest, latest(_time) AS Latest by sourcetype source host | eval Earliest=strftime(Earliest,"%+") | eval Latest=strftime(Latest,"%+") | sort - count`

## Check for any historical IP traffic outbound to the published IOCs with any applicable logs
`search index=* index!=bro index!=appwebext 54.193.127.66 OR 54.215.192.52 OR 34.203.203.23 OR 139.99.115.204 OR 5.252.177.25 OR 204.188.205.176 OR 51.89.125.18 OR 167.114.213.199 OR 13.59.205.66 OR 5.252.177.21 | stats count earliest(_time) AS Earliest, latest(_time) AS Latest by index sourcetype source host | eval Earliest=strftime(Earliest,"%+") | eval Latest=strftime(Latest,"%+") | sort - count`


