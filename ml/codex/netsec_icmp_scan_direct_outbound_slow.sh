###################################################################################################
# (C)Copyright 2021 ElastiFlow Inc.
# All Rights Reserved
# 
# RESTRICTED RIGHTS
# 
# This software is supplied under the terms of the applicable license agreement established between
# ElastiFlow Inc. and the End User.
# 
# Use, copying, publishing, repackaging, reselling, retransmitting, redistributing, or disclosing
# the software is strictly prohibited unless otherwise provided in the license agreement. Any copy
# must contain the above copyright notice and this restricted rights notice.
# 
# UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING. THE SOFTWARE IS PROVIDED "AS IS",
# WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS. IN
# NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###################################################################################################

#!/bin/bash

while getopts h:u:p: flag
do
  case "${flag}" in
    h) ES_HOST=${OPTARG};;
    u) USERNAME=${OPTARG};;
    p) PASSWORD=${OPTARG};;
  esac
done

if [[ "$ES_HOST" = "" ]]; then
  ES_HOST=http://127.0.0.1:9200
fi

if [[ "$USERNAME" = "" ]]; then
  USERNAME=elastic
fi

if [[ "$PASSWORD" = "" ]]; then
  PASSWORD=changeme
fi

DETECTOR=$( cat << EOF
{
  "job_type": "anomaly_detector",
  "description": "ICMP Scan Direct - outbound (slow)",
  "groups": [
    "elastiflow",
    "security",
    "reconnaissance"
  ],
  "analysis_config": {
    "bucket_span": "240m",
    "detectors": [
      {
        "detector_description": "High Unique Destination IPs",
        "function": "high_distinct_count",
        "field_name": "flow.dst.ip.addr",
        "over_field_name": "flow.src.ip.addr",
        "detector_index": 0
      }
    ],
    "influencers": [
      "flow.src.ip.addr",
      "flow.src.host.name"
    ]
  },
  "analysis_limits": {
    "model_memory_limit": "1024mb"
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": false,
    "annotations_enabled": true
  },
  "model_snapshot_retention_days": 10,
  "daily_model_snapshot_retention_after_days": 1,
  "custom_settings": {
    "custom_urls": [
      {
        "url_name": "RiskIQ PassiveTotal",
        "url_value": "https://community.riskiq.com/research?query=\$flow.src.ip.addr$"
      },
      {
        "url_name": "Flow Records",
        "url_value": "dashboards#/view/bf9f8a70-3d3f-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.ip.addr,negate:!f,params:(query:'\$flow.src.ip.addr$'),type:phrase),query:(match_phrase:(flow.src.ip.addr:'\$flow.src.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:!(ICMP,IPv6-ICMP),type:phrases),query:(bool:(minimum_should_match:1,should:!((match_phrase:(l4.proto.name:'ICMP')),(match_phrase:(l4.proto.name:'IPv6-ICMP')))))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:icmp.type.name,negate:!f,params:(query:'Echo'),type:phrase),query:(match_phrase:(icmp.type.name:'Echo'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.dst.as.org,negate:!t,params:(query:'PRIVATE'),type:phrase),query:(match_phrase:(flow.dst.as.org:'PRIVATE'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.as.org,negate:!f,params:(query:'PRIVATE'),type:phrase),query:(match_phrase:(flow.src.as.org:'PRIVATE')))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      }
    ]
  },
  "results_index_name": "custom-elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow",
  "allow_lazy_open": false
}
EOF
)

DATAFEED=$( cat << EOF
{
  "job_id": "elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow",
  "indices": [
    "elastiflow-flow-codex-*"
  ],
  "query": {
    "bool": {
      "must": [
        {
          "exists": {
            "field": "flow.src.ip.addr"
          }
        },
        {
          "exists": {
            "field": "flow.dst.ip.addr"
          }
        },
        {
          "terms": {
            "l4.proto.name": [
              "ICMP",
              "IPv6-ICMP"
            ]
          }
        },
        {
          "term": {
            "icmp.type.name": "Echo"
          }
        },
        {
          "term": {
            "flow.src.as.org": "PRIVATE"
          }
        }
      ],
      "must_not": [
        {
          "term": {
            "flow.dst.as.org": "PRIVATE"
          }
        },
        {
          "terms": {
            "flow.src.ip.addr": [
            ]
          }
        },
        {
          "terms": {
            "flow.dst.ip.addr": [
            ]
          }
        }
      ]
    }
  },
  "scroll_size": 1000,
  "chunking_config": {
    "mode": "auto"
  },
  "delayed_data_check_config": {
    "enabled": true
  },
  "indices_options": {
    "expand_wildcards": [
      "open"
    ],
    "ignore_unavailable": false,
    "allow_no_indices": true,
    "ignore_throttled": true
  }
}
EOF
)

echo ""; echo "Installing anomaly_detector elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow ..."
curl -XPUT -o /dev/null -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/anomaly_detectors/elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow?pretty -H "Content-Type: application/json" -d "${DETECTOR}"
echo ""; echo "Installing datafeed elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow ..."
curl -XPUT -o /dev/null -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/datafeeds/datafeed-elastiflow_ecs_netsec_icmp_scan_direct_outbound_slow?pretty -H "Content-Type: application/json" -d "${DATAFEED}"