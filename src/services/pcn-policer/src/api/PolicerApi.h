/**
* policer API generated from policer.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* PolicerApi.h
*
*/

#pragma once

#define POLYCUBE_SERVICE_NAME "policer"


#include "polycube/services/response.h"
#include "polycube/services/shared_lib_elements.h"

#include "ContractJsonObject.h"
#include "ContractUpdateDataInputJsonObject.h"
#include "DefaultContractJsonObject.h"
#include "DefaultContractUpdateDataInputJsonObject.h"
#include "PolicerJsonObject.h"
#include <vector>


#ifdef __cplusplus
extern "C" {
#endif

Response create_policer_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_policer_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_policer_contract_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_policer_contract_update_data_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_policer_default_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response create_policer_default_contract_update_data_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response delete_policer_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_policer_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_policer_contract_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response delete_policer_default_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_contract_action_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_contract_burst_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_contract_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_contract_rate_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_default_contract_action_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_default_contract_burst_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_default_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_default_contract_rate_limit_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response read_policer_list_by_id_handler(const char *name, const Key *keys, size_t num_keys);
Response replace_policer_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_policer_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_policer_contract_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response replace_policer_default_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_policer_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_policer_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_policer_contract_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_policer_default_contract_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);
Response update_policer_list_by_id_handler(const char *name, const Key *keys, size_t num_keys, const char *value);

Response policer_contract_list_by_id_help(const char *name, const Key *keys, size_t num_keys);
Response policer_list_by_id_help(const char *name, const Key *keys, size_t num_keys);


#ifdef __cplusplus
}
#endif

