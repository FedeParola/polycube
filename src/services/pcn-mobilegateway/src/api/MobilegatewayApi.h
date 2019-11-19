/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* MobilegatewayApi.h
*
*/

#pragma once

#define POLYCUBE_SERVICE_NAME "mobilegateway"


#include "polycube/services/response.h"
#include "polycube/services/shared_lib_elements.h"

#include "ArpTableJsonObject.h"
#include "BaseStationJsonObject.h"
#include "MobilegatewayJsonObject.h"
#include "PortsJsonObject.h"
#include "PortsSecondaryipJsonObject.h"
#include "RouteJsonObject.h"
#include "UserEquipmentJsonObject.h"
#include <vector>


#ifdef __cplusplus
extern "C" {
#endif

Response create_mobilegateway_arp_table_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_arp_table_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_base_station_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_base_station_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_ports_secondaryip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_ports_secondaryip_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_route_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_route_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_user_equipment_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_mobilegateway_user_equipment_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response delete_mobilegateway_arp_table_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_arp_table_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_base_station_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_base_station_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_ports_secondaryip_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_ports_secondaryip_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_route_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_route_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_user_equipment_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_mobilegateway_user_equipment_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_arp_table_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_arp_table_interface_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_arp_table_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_arp_table_mac_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_base_station_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_base_station_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_direction_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_ip_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_mac_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_secondaryip_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_ports_secondaryip_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_route_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_route_interface_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_route_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_route_pathcost_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_user_equipment_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_user_equipment_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_user_equipment_rate_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_user_equipment_teid_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_mobilegateway_user_equipment_tunnel_endpoint_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response replace_mobilegateway_arp_table_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_arp_table_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_base_station_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_base_station_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_ports_secondaryip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_ports_secondaryip_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_route_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_route_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_user_equipment_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_mobilegateway_user_equipment_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_arp_table_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_arp_table_interface_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_arp_table_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_arp_table_mac_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_base_station_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_base_station_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_direction_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_ip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_mac_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_secondaryip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_ports_secondaryip_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_route_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_route_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_route_pathcost_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_user_equipment_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_user_equipment_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_user_equipment_rate_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_user_equipment_teid_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_mobilegateway_user_equipment_tunnel_endpoint_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);

Response mobilegateway_arp_table_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_base_station_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_ports_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_ports_secondaryip_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_route_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response mobilegateway_user_equipment_list_by_id_help(const char *name, const Key *keys, size_t num_keys);


#ifdef __cplusplus
}
#endif
