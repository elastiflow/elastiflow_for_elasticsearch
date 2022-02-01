###################################################################################################
# (C)Copyright 2022 ElastiFlow Inc.
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
  "description": "Generic DDoS Attack (UDP Amplification) - edge",
  "groups": [
    "elastiflow",
    "security",
    "ddos"
  ],
  "analysis_config": {
    "bucket_span": "5m",
    "detectors": [
      {
        "detector_description": "Excessive UDP Responders",
        "function": "high_distinct_count",
        "field_name": "source.ip",
        "by_field_name": "destination.ip",
        "partition_field_name": "source.port",
        "detector_index": 0
      }
    ],
    "influencers": [
      "destination.ip",
      "destination.domain",
      "source.port",
      "flow.src.l4.port.name"
    ]
  },
  "analysis_limits": {
    "model_memory_limit": "3072mb"
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
        "url_name": "Top Talkers",
        "url_value": "dashboards#/view/a000b640-3d3e-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.as.organization.name,negate:!t,params:(query:'PRIVATE'),type:phrase),query:(match_phrase:(source.as.organization.name:'PRIVATE'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.port,negate:!f,params:(query:'\$source.port$'),type:phrase),query:(match_phrase:(source.port:'\$source.port$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:network.transport,negate:!f,params:(query:'udp'),type:phrase),query:(match_phrase:(network.transport:'udp'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:destination.ip,negate:!f,params:(query:'\$destination.ip$'),type:phrase),query:(match_phrase:(destination.ip:'\$destination.ip$')))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Flow Records",
        "url_value": "dashboards#/view/bf9f8a70-3d3f-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.as.organization.name,negate:!t,params:(query:'PRIVATE'),type:phrase),query:(match_phrase:(source.as.organization.name:'PRIVATE'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.port,negate:!f,params:(query:'\$source.port$'),type:phrase),query:(match_phrase:(source.port:'\$source.port$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:network.transport,negate:!f,params:(query:'udp'),type:phrase),query:(match_phrase:(network.transport:'udp'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:destination.ip,negate:!f,params:(query:'\$destination.ip$'),type:phrase),query:(match_phrase:(destination.ip:'\$destination.ip$')))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      }
    ]
  },
  "results_index_name": "custom-elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge",
  "allow_lazy_open": false
}
EOF
)

DATAFEED=$( cat << EOF
{
  "job_id": "elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge",
  "indices": [
    "elastiflow-flow-ecs-*"
  ],
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "network.transport": "udp"
          }
        },
        {
          "exists": {
            "field": "source.port"
          }
        },
        {
          "exists": {
            "field": "source.ip"
          }
        },
        {
          "exists": {
            "field": "destination.ip"
          }
        }
      ],
      "must_not": [
        {
          "term": {
            "source.as.organization.name": "PRIVATE"
          }
        },
        {
          "term": {
            "destination.as.organization.name": "PRIVATE"
          }
        },
        {
          "terms": {
            "source.port": [
              80,
              443,
              8080,
              17,
              19,
              53,
              69,
              111,
              123,
              137,
              161,
              389,
              520,
              751,
              1434,
              1645,
              1646,
              1812,
              1813,
              1900,
              3702,
              5093,
              5353,
              11211,
              27015,
              27960
            ]
          }
        },
        {
          "terms": {
            "source.ip": [
            ]
          }
        },
        {
          "terms": {
            "destination.ip": [
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

echo ""; echo "Installing anomaly_detector elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/anomaly_detectors/elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge?pretty -H "Content-Type: application/json" -d "${DETECTOR}"
echo ""; echo "Installing datafeed elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/datafeeds/datafeed-elastiflow_ecs_netsec_ddos_generic_udp_amplify_edge?pretty -H "Content-Type: application/json" -d "${DATAFEED}"
