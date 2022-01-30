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

echo ""; echo "Installing all CODEX-compatible anomaly_detectors and datafeeds ..."; echo ""
./avail_tcp_sess_fails_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./avail_tcp_sess_fails_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./avail_tcp_sess_fails_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_bruteforce_direct_cli_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_cli_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_cli_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_bruteforce_direct_desktop_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_direct_desktop_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_bruteforce_distrib_desktop_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_ddos_generic_tcp.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ddos_generic_udp_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_icmp_flood_ddos_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_ddos_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_ddos_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_direct_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_direct_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_flood_direct_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_icmp_scan_direct_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_icmp_scan_direct_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_chargen_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_dns_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_kad_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ldap_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_mdns_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_memcached_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_mssql_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_netbios_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ntp_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_qotd_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_quake_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_radius_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rip_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rpc_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_sentinel_spss_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_snmp_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_ssdp_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_steam_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_tftp_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_wsd_amplify.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_port_scan_direct_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_direct_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_all_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_all_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_in_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_in_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_out_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_out_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_priv_fast.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_port_scan_distrib_priv_slow.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_rare_asn_client.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_asn_server.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_conversation_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_conversation_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_conversation_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_geo_country_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_geo_country_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_rare_geo_country_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./netsec_syn_flood_ddos_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_ddos_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_ddos_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_direct_in.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_direct_out.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./netsec_syn_flood_direct_priv.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}

./perf_asn_dst_thruput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_asn_src_thruput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_netif_egress_thruput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
./perf_netif_ingress_thruput.sh -h ${ES_HOST} -u ${USERNAME} -p ${PASSWORD}
