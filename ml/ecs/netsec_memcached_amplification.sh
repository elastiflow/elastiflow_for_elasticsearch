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
  "description": "Memcached Amplification Attack",
  "groups": [
    "elastiflow",
    "security",
    "ddos"
  ],
  "analysis_config": {
    "bucket_span": "5m",
    "detectors": [
      {
        "detector_description": "Excessive Memcached Responders",
        "function": "high_distinct_count",
        "field_name": "source.ip",
        "partition_field_name": "destination.domain",
        "detector_index": 0
      }
    ],
    "influencers": [
      "destination.domain"
    ]
  },
  "analysis_limits": {
    "model_memory_limit": "2048mb",
    "categorization_examples_limit": 4
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
        "url_value": "dashboards#/view/a000b640-3d3e-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),exists:(field:source.as.number),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.as.number,negate:!f,type:exists,value:exists)),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.port,negate:!f,params:(query:'11211'),type:phrase),query:(match_phrase:(source.port:'11211'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:network.transport,negate:!f,params:(query:'udp'),type:phrase),query:(match_phrase:(network.transport:'udp'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:destination.domain,negate:!f,params:(query:'\$destination.domain$'),type:phrase),query:(match_phrase:(destination.domain:'\$destination.domain$')))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Flow Records",
        "url_value": "dashboards#/view/bf9f8a70-3d3f-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),exists:(field:source.as.number),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.as.number,negate:!f,type:exists,value:exists)),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:source.port,negate:!f,params:(query:'11211'),type:phrase),query:(match_phrase:(source.port:'11211'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:network.transport,negate:!f,params:(query:'udp'),type:phrase),query:(match_phrase:(network.transport:'udp'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-ecs-*',key:destination.domain,negate:!f,params:(query:'\$destination.domain$'),type:phrase),query:(match_phrase:(destination.domain:'\$destination.domain$')))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      }
    ]
  },
  "results_index_name": "custom-elastiflow_ecs_netsec_memcached_amplification",
  "allow_lazy_open": false
}
EOF
)

DATAFEED=$( cat << EOF
{
  "job_id": "elastiflow_ecs_netsec_memcached_amplification",
  "indices": [
    "elastiflow-flow-ecs-*"
  ],
  "query": {
    "bool": {
      "must": [
        {
          "exists": {
            "field": "source.as.number"
          }
        },
        {
          "term": {
            "network.transport": "udp"
          }
        },
        {
          "term": {
            "source.port": 11211
          }
        },
        {
          "exists": {
            "field": "source.domain"
          }
        },
        {
          "exists": {
            "field": "destination.domain"
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

echo ""; echo "Installing anomaly_detector elastiflow_ecs_netsec_memcached_amplification ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/anomaly_detectors/elastiflow_ecs_netsec_memcached_amplification?pretty -H "Content-Type: application/json" -d "${DETECTOR}"
echo ""; echo "Installing datafeed elastiflow_ecs_netsec_memcached_amplification ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/datafeeds/datafeed-elastiflow_ecs_netsec_memcached_amplification?pretty -H "Content-Type: application/json" -d "${DATAFEED}"
