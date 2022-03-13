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
  "description": "Low NTP Request/Response Ratio",
  "groups": [
    "elastiflow",
    "availability",
    "network_services"
  ],
  "analysis_config": {
    "bucket_span": "20m",
    "detectors": [
      {
        "detector_description": "Low NTP Request/Response Ratio",
        "function": "low_mean",
        "field_name": "ratio",
        "partition_field_name": "flow.server.ip.addr",
        "detector_index": 0
      }
    ],
    "influencers": [
      "flow.server.ip.addr"
    ],
    "summary_count_field_name": "doc_count"
  },
  "analysis_limits": {
    "model_memory_limit": "256mb"
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
        "url_value": "dashboards#/view/e2888380-9d73-11ec-a4df-e940aaa4214d?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.ip.addr,negate:!f,params:(query:'\$flow.server.ip.addr$'),type:phrase),query:(match_phrase:(flow.server.ip.addr:'\$flow.server.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.server.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Top Talkers",
        "url_value": "dashboards#/view/a000b640-3d3e-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.ip.addr,negate:!f,params:(query:'\$flow.server.ip.addr$'),type:phrase),query:(match_phrase:(flow.server.ip.addr:'\$flow.server.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.server.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      },
      {
        "url_name": "Flow Records",
        "url_value": "dashboards#/view/bf9f8a70-3d3f-11eb-bc2c-c5758316d788?_g=(filters:!(('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.ip.addr,negate:!f,params:(query:'\$flow.server.ip.addr$'),type:phrase),query:(match_phrase:(flow.server.ip.addr:'\$flow.server.ip.addr$'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:l4.proto.name,negate:!f,params:(query:'UDP'),type:phrase),query:(match_phrase:(l4.proto.name:'UDP'))),('\$state':(store:globalState),meta:(alias:!n,disabled:!f,index:'elastiflow-flow-codex-*',key:flow.server.l4.port.id,negate:!f,params:(query:123),type:phrase),query:(match_phrase:(flow.server.l4.port.id:123)))),refreshInterval:(pause:!t,value:0),time:(mode:absolute,from:'\$earliest$',to:'\$latest$'))"
      }
    ]
  },
  "results_index_name": "custom-elastiflow_codex_avail_ntp_resp_ratio_low",
  "allow_lazy_open": false
}
EOF
)

DATAFEED=$( cat << EOF
{
  "job_id": "elastiflow_codex_avail_ntp_resp_ratio_low",
  "indices": [
    "elastiflow-flow-codex-*"
  ],
  "aggregations": {
    "buckets": {
      "date_histogram": {
        "field": "@timestamp",
        "fixed_interval": "20m",
        "time_zone": "UTC"
      },
      "aggregations": {
        "@timestamp": {
          "max": {
            "field": "@timestamp"
          }
        },
        "flow.server.ip.addr": {
          "terms": {
            "field": "flow.server.ip.addr",
            "size": 20000
          },
          "aggregations": {
            "requests": {
              "filter": {
                "term": {
                  "flow.dst.l4.port.id": 123
                }
              },
              "aggregations": {
                "packets": {
                  "sum": {
                    "field": "flow.packets"
                  }
                }
              }
            },
            "responses": {
              "filter": {
                "term": {
                  "flow.src.l4.port.id": 123
                }
              },
              "aggregations": {
                "packets": {
                  "sum": {
                    "field": "flow.packets"
                  }
                }
              }
            },
            "ratio": {
              "bucket_script": {
                "buckets_path": {
                  "requests": "requests.packets",
                  "responses": "responses.packets"
                },
                "script": "if(params.requests>0){params.responses/params.requests}else{1}"
              }
            }
          }
        }
      }
    }
  },
  "query": {
    "bool": {
      "must": [
        {
          "terms": {
            "flow.export.type": [
              "netflow",
              "ipfix"
            ]
          }
        },
        {
          "term": {
            "l4.proto.name": "UDP"
          }
        },
        {
          "term": {
            "flow.server.l4.port.id": 123
          }
        },
        {
          "exists": {
            "field": "flow.client.ip.addr"
          }
        },
        {
          "exists": {
            "field": "flow.server.ip.addr"
          }
        }
      ],
      "must_not": [
        {
          "term": {
            "flow.client.l4.port.id": 123
          }
        },
        {
          "terms": {
            "flow.client.ip.addr": [
            ]
          }
        },
        {
          "terms": {
            "flow.server.ip.addr": [
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

echo ""; echo "Installing anomaly_detector elastiflow_codex_avail_ntp_resp_ratio_low ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/anomaly_detectors/elastiflow_codex_avail_ntp_resp_ratio_low?pretty -H "Content-Type: application/json" -d "${DETECTOR}"
echo ""; echo "Installing datafeed elastiflow_codex_avail_ntp_resp_ratio_low ..."
curl -XPUT -u ${USERNAME}:${PASSWORD} -k ${ES_HOST}/_ml/datafeeds/datafeed-elastiflow_codex_avail_ntp_resp_ratio_low?pretty -H "Content-Type: application/json" -d "${DATAFEED}"
