# Useful Splunk Searches

## Search for Event code 4624 (any logins to the Solarwinds server) - find out credentials that could be compromised. 
```
search index=my_windows_events_index solarwinds* "EventCode=4624" Workstation_Name="solarwinds*"
| stats count min(_time) AS first_time max(_time) AS last_time by Workstation_Name Security_ID Logon_Type 
| convert timeformat="%d/%m/%Y %H:%M:%S" ctime(*_time)
| sort count
```

## Check Bro for any Solarwinds DNS lookups -  find any unknown or test instances of Solarwinds
```
search index=my_bro_logs_index sourcetype=bro_dns query="solarwinds.com"
| rex field=_raw "(^\d+\.\d+\s\S+\s)(?<src_ip>\d+\.\d+\.\d+\.\d+)"
| search src_ip IN ("solarwinds_ip","solarwinds_ip","solarwinds_ip","solarwinds_ip")
```

## Check for any historical HTTP/S traffic outbound to published IOCs with any applicable http/s logs
```
search index=my_bro_logs_index deftsecurity.com OR freescanonline.com OR thedoccloud.com OR thedoccloud.com OR websitetheme.com OR highdatabase.com OR incomeupdate.com OR databasegalore.com OR panhardware.com OR zupertech.com OR appsync-api.eu-west-1.avsvmcloud.com OR appsync-api.eu-west-1.avsvmcloud.com OR appsync-api.us-east-2.avsvmcloud.com OR appsync-api.us-west-2.avsvmcloud.com OR appsync-api.us-west-2.avsvmcloud.com OR appsync-api.eu-west-1.avsvmcloud.com | stats count earliest(_time) AS Earliest, latest(_time) AS Latest by sourcetype source host | eval Earliest=strftime(Earliest,"%+") | eval Latest=strftime(Latest,"%+") | sort - count
```

## Check for any historical IP traffic outbound to the published IOCs with any applicable logs
```
search index=my_bro_logs_index 54.193.127.66 OR 54.215.192.52 OR 34.203.203.23 OR 139.99.115.204 OR 5.252.177.25 OR 204.188.205.176 OR 51.89.125.18 OR 167.114.213.199 OR 13.59.205.66 OR 5.252.177.21 | stats count earliest(_time) AS Earliest, latest(_time) AS Latest by index sourcetype source host | eval Earliest=strftime(Earliest,"%+") | eval Latest=strftime(Latest,"%+") | sort - count
```

## If you have TLS decrpytion in place/have decrypted traffic in your Bro logs then you should also search for the hashes
```
index=my_bro_logs_index sourcetype=bro_files sha256=d0d626deb3f9484e649294a8dfa814c5568f846d5aa02d4cdad5d041a29d5600 OR sha256=53f8dfc65169ccda021b72a62e0c22a4db7c4077f002fa742717d41b3c40f2c7 OR sha256=019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134 OR sha256=ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6 OR sha256=32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77 OR sha256=292327e5c94afa352cc5a02ca273df543f2020d0e76368ff96c84f4e90778712 OR sha256=c15abaf51e78ca56c0376522d699c978217bf041a3bd3c71d09193efa5717c71 OR sha256=019085a76ba7126fff22770d71bd901c325fc68ac55aa743327984e89f4b0134 OR sha256=ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6 OR sha256=32519b85c0b422e4656de6e6c41878e95fd95026267daab4215ee59c107d6c77 | stats count earliest(_time) AS Earliest, latest(_time) AS Latest by sourcetype source host | eval Earliest=strftime(Earliest,"%+") | eval Latest=strftime(Latest,"%+") | sort - count
```