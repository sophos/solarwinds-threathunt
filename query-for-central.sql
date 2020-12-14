/*****************************************************************************************\
| First we have to get the file from GIT then cut it into lines                           |
| We then convert each line into its component parts as a table                           |
| Each line has an identified IOC Type, Indicator and Notes so we will use some string    |
| functions to seperate each element into our IOC_List                                    |
\*****************************************************************************************/
WITH IOC_LIST (IOC_Type, Indicator, note) AS (
 WITH IOC_FILE(Line, str) AS (
  SELECT 'ip,127.0.0.1,TEST DATA', (SELECT result from curl where url = '$$RAW IOC List location from a URL$$') ||char(10)
  UNION ALL
  SELECT substr(str, 0, instr(str, char(10) )), substr(str, instr(str, char(10) )+1) FROM IOC_FILE WHERE str!=''
 )
SELECT
 replace(Line, ltrim(Line, replace(Line, ',', '')), '') 'Indicator Type', /* IOC type */
 replace(replace(substr(Line, instr(Line, ',')+1), ltrim(substr(Line, instr(Line, ',')+1), replace(substr(Line, instr(Line, ',')+1), ',', '')), ''),'*','%')  Indicator,       /* Actual IOC Data */ /* Convert wildcard * to % */
 replace(Line, rtrim(Line, replace(Line, ',', '')), '') 'Note' /* Note */
FROM IOC_FILE WHERE Line != '' AND Line != 'Indicator type,Data,Note' AND Line NOT LIKE 'Description%' AND Line NOT LIKE '%TEST DATA%' AND Line NOT LIKE '%indicator_type%'
)

--SELECT IOC_Type, CAST(LOWER('%'||Indicator||'%') AS TEXT), note FROM IOC_LIST -- Uncomment this line out to check if we are importing the IOC data correctly 

/************************************************************************\
| OK that should give us a table of IOCs to go hunt for                  |
| Enable the line below to just dump the table to confirm all is working |
| SELECT * from IOC_LIST;                                                |    
\************************************************************************/

/**********************************************************************\
| The admin may want to search a large amount of data in the tables so |
| split time into 20 min chunks given the number hours specified       |
\**********************************************************************/

, for(x) AS (
   VALUES ( (CAST ($$Start Search From$$ AS INT) ) )
   UNION ALL
   SELECT x+1200 FROM for WHERE x < (CAST ($$Start Search From$$ AS INT) + CAST( ($$Number of Hours of activity to search$$ * 3600) AS INT))
)

/****************************************************************************\
| Check for matching domain or URL info seen in the specified lookback period|
\****************************************************************************/

SELECT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, '\', '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.url
FROM for
 LEFT JOIN IOC_LIST ioc ON LOWER(ioc.IOC_Type) IN('domain', 'url')
 LEFT JOIN sophos_process_activity spa ON spa.subject IN ('Http','Url','Network') AND spa.time >= for.x and spa.time <= for.x+1200  
WHERE spa.url LIKE ioc.indicator

UNION ALL

/****************************************************************************\
| Check for matching IP info seen in the specified lookback period           |
\****************************************************************************/

SELECT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, '\', '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.url
FROM for
 LEFT JOIN IOC_LIST ioc ON LOWER(ioc.IOC_Type) IN('ip')
 LEFT JOIN sophos_process_activity spa ON spa.subject IN ('Http','Ip','Network') AND spa.time >= for.x and spa.time <= for.x+1200  
WHERE spa.source LIKE ioc.Indicator OR spa.destination LIKE ioc.Indicator

UNION ALL

/***********************************************************************************\
| Check for matching port info seen in the specified lookback period|
\***********************************************************************************/

SELECT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, '\', '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.destinationPort
FROM for
 LEFT JOIN IOC_LIST ioc ON LOWER(ioc.IOC_Type) IN('port')
 LEFT JOIN sophos_process_activity spa ON spa.subject IN ('Http','Ip','Network') AND spa.time >= for.x and spa.time <= for.x+1200  
WHERE spa.destinationPort LIKE ioc.Indicator

UNION ALL

/***********************************************************************************\
| Check for matching sha256 info seen in the specified lookback period|
\***********************************************************************************/

SELECT
 CAST( datetime(spj.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 'sophos_process_journal',
 spj.SophosPID,
 CAST ( (select replace(spj.pathname, rtrim(spj.pathname, replace(spj.pathname, '\', '')), '')) AS TEXT) process_name,
 spj.eventtype,
 'process execution',
 spj.sha256
FROM for
 LEFT JOIN IOC_LIST ioc ON LOWER(ioc.IOC_Type) IN('sha256')
 LEFT JOIN sophos_process_journal spj ON spj.time >= for.x and spj.time <= for.x+1200  

WHERE LOWER(spj.sha256) LIKE LOWER(ioc.Indicator)

UNION ALL

/***********************************************************************************\
| Check for matching process activity info seen in the specified lookback period|
\***********************************************************************************/

SELECT
 CAST( datetime(spa.time,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 spa.subject,
 spa.SophosPID,
 CAST ( (select replace(spa.pathname, rtrim(spa.pathname, replace(spa.pathname, '\', '')), '')) AS TEXT) process_name,
 spa.action,
 spa.object,
 spa.pathname
FROM for
 LEFT JOIN IOC_LIST ioc ON LOWER(ioc.IOC_Type) IN('pathname', 'file_path', 'file_path_name', 'filename')
 LEFT JOIN sophos_process_activity spa ON spa.subject IN ('Image','Process') AND spa.time >= for.x and spa.time <= for.x+1200  
WHERE LOWER(spa.pathname) LIKE LOWER(ioc.Indicator) OR LOWER(spa.object) LIKE LOWER(ioc.Indicator)

UNION ALL

/***********************************************************************************\
| Check for matching file/directory on the CURRENT SATE of the device               |
\***********************************************************************************/

SELECT DISTINCT
 CAST( datetime(file.btime,'unixepoch') AS TEXT) DATE_TIME,
 'MATCH FOUND' Detection,
 ioc.IOC_Type,
 ioc.Indicator,
 ioc.note,
 'File_system',
 '' ,
 file.filename,
 'on disk',
 file.path,
 ''
FROM IOC_LIST ioc 
 LEFT JOIN file ON LOWER(ioc.IOC_Type) IN('pathname', 'file_path', 'file_path_name', 'filename') AND file.path LIKE ioc.indicator
WHERE DATE_TIME <> ''
