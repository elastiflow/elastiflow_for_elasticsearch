# Elastic Machine Learning

This folder provides scripts to install jobs for Elastic's Machine Learning features (these features require an Elastic subscription).

> NOTE: More ML jobs are coming, as well as Detectors for the Elastic Security app related to these ML jobs.

## Installation

Each script will install both the `anomaly_detector` and `datafeed` via the Elasticsearch REST API.

The syntax is: `<script name> -h <elasticsearch url> -u <username> -p <password>`

For example:

```
./netsec_port_scan_fast.sh -h https://192.0.2.11:9200 -u elastic -p changeme
```

After installing the job you can start it from the _Anomaly Detection -> Job Management_ page of the Kibana Machine Learning app.

## Drill Down Links

Each job includes custom URL definitions that allow you to drill-down into the raw flow data. These links for each anomaly in the Anomaly Explorer.

![image](https://user-images.githubusercontent.com/10326954/112114812-c331db80-8bb8-11eb-9116-b6780106077e.png)

Select the dashboard which you would like to launch...

![image](https://user-images.githubusercontent.com/10326954/112115353-61be3c80-8bb9-11eb-8e95-86d5bd35a30d.png)

... or, where possible, launch RiskIQ PassiveTotal Intelligence.

![image](https://user-images.githubusercontent.com/10326954/112115668-be215c00-8bb9-11eb-98c6-045e6e282b6c.png)
