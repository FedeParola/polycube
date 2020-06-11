/**
* classifier API generated from classifier.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* ClassifierApi.h
*
*/

#pragma once

#define POLYCUBE_SERVICE_NAME "classifier"


#include "polycube/services/response.h"
#include "polycube/services/shared_lib_elements.h"

#include "ClassifierJsonObject.h"
#include "TrafficClassJsonObject.h"
#include <vector>


#ifdef __cplusplus
extern "C" {
#endif

Response create_classifier_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_classifier_traffic_class_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_classifier_traffic_class_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response delete_classifier_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_classifier_traffic_class_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_classifier_traffic_class_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_direction_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_dmac_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_dport_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_dstip_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_ethtype_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_l4proto_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_priority_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_smac_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_sport_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_classifier_traffic_class_srcip_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response replace_classifier_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_classifier_traffic_class_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_classifier_traffic_class_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_direction_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_dmac_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_dport_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_dstip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_ethtype_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_l4proto_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_priority_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_smac_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_sport_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_classifier_traffic_class_srcip_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);

Response classifier_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response classifier_traffic_class_list_by_id_help(const char *name, const Key *keys, size_t num_keys);


#ifdef __cplusplus
}
#endif
