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

echo ""; echo "Installing all ECS-compatible anomaly_detectors and datafeeds ..."; echo ""
./avail_tcp_sess_fails_private.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./avail_tcp_sess_fails_public.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_brute_force_cli.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_chargen_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ddos_generic_tcp.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ddos_generic_udp_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_dns_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_ddos.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_direct.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_kad_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ldap_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_mdns_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_memcached_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_mssql_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_netbios_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ntp_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_qotd_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_quake_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_radius_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_asn_client.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_asn_server.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_conversation_private.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_conversation_public.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rip_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rpc_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_sentinel_spss_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_snmp_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ssdp_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_steam_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_ddos.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_direct.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_tftp_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_wsd_amplification.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_asn_dst_throughput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_asn_src_throughput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_netif_egress_throughput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_netif_ingress_throughput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
