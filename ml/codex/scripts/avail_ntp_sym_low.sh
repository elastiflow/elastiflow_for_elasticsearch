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
  "description": "Low NTP Symmetric Messages",
  "groups": [
    "elastiflow",
    "availability",
    "network_services"
  ],
  "analysis_config": {
    "bucket_span": "20m",
    "detectors": [
      {
        "detector_description": "Low NTP Symmetric Messages",
        "function": "low_count",
        "by_field_name": "flow.src.ip.addr",
        "partition_field_name": "flow.export.host.name",
        "detector_index": 0
      }
    ],
    "influencers": [
      "flow.export.host.name",
      "flow.src.ip.addr",
      "flow.src.host.name",
      "flow.dst.ip.addr",
      "flow.dst.host.name"
    ]
  },
  "analysis_limits": {
    "model_memory_limit": "512mb"
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": true,
    "annotations_enabled": true
  },
  "model_snapshot_retention_days": 7,
  "daily_model_snapshot_retention_after_days": 1,
  "custom_settings": {
    "custom_urls": [
      {
        "url_name": "Core Services (NTP)",
        "url_value": "dashboards#/view/e2888380-9d73-11ec-a4df-e940aaa4214d?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.export.host.name,negate:!f,params:(query:'\$flow.export.host.name$'),type:phrase),query:(match_phrase:(flow.export.host.name:'\$flow.export.host.name$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.ip.addr,negate:!f,params:(query:'\$flow.src.ip.addr$'),type:phrase),query:(match_phrase:(flow.src.ip.addr:'\$flow.src.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.src.l4.port.id:123))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.dst.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.dst.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Top Talkers",
        "url_value": "dashboards#/view/a000b640-3d3e-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.export.host.name,negate:!f,params:(query:'\$flow.export.host.name$'),type:phrase),query:(match_phrase:(flow.export.host.name:'\$flow.export.host.name$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.ip.addr,negate:!f,params:(query:'\$flow.src.ip.addr$'),type:phrase),query:(match_phrase:(flow.src.ip.addr:'\$flow.src.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.src.l4.port.id:123))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.dst.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.dst.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Flow Records",
        "url_value": "dashboards#/view/abfed250-3d3f-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.export.host.name,negate:!f,params:(query:'\$flow.export.host.name$'),type:phrase),query:(match_phrase:(flow.export.host.name:'\$flow.export.host.name$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.ip.addr,negate:!f,params:(query:'\$flow.src.ip.addr$'),type:phrase),query:(match_phrase:(flow.src.ip.addr:'\$flow.src.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.src.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.src.l4.port.id:123))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.dst.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.dst.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      }
    ]
  },
  "results_index_name": "custom-elastiflow_codex_avail_ntp_sym_low",
  "allow_lazy_open": false
}
EOF
)

DATAFEED=$( cat << EOF
{
  "job_id": "elastiflow_codex_avail_ntp_sym_low",
  "indices": [
    "elastiflow-flow-codex-*"
  ],
  "query": {
    "bool": {
      "must": [
        {
          "term": {
            "l4.proto.name": "UDP"
          }
        },
        {
          "term": {
            "flow.src.l4.port.id": 123
          }
        },
        {
          "term": {
            "flow.dst.l4.port.id": 123
          }
        },
        {
          "exists": {
            "field": "flow.export.host.name"
          }
        },
        {
          "exists": {
            "field": "flow.src.ip.addr"
          }
        },
        {
          "exists": {
            "field": "flow.dst.ip.addr"
          }
        }
      ],
      "must_not": [
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

echo ""; echo "Installing anomaly_detector elastiflow_codex_avail_ntp_sym_low ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/anomaly_detectors/elastiflow_codex_avail_ntp_sym_low?pretty -H "Content-Type: application/json" -d "${DETECTOR}"
echo ""; echo "Installing datafeed elastiflow_codex_avail_ntp_sym_low ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/datafeeds/datafeed-elastiflow_codex_avail_ntp_sym_low?pretty -H "Content-Type: application/json" -d "${DATAFEED}"
