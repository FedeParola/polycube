/**
* trafficclassifier API generated from trafficclassifier.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* TrafficclassifierApiImpl.h
*
*
*/

#pragma once


#include <memory>
#include <map>
#include <mutex>
#include "../Trafficclassifier.h"

#include "TrafficClassJsonObject.h"
#include "TrafficclassifierJsonObject.h"
#include <vector>

namespace polycube {
namespace service {
namespace api {

using namespace polycube::service::model;

namespace TrafficclassifierApiImpl {
  void create_trafficclassifier_by_id(const std::string &name, const TrafficclassifierJsonObject &value);
  void create_trafficclassifier_traffic_class_by_id(const std::string &name, const uint32_t &id, const TrafficClassJsonObject &value);
  void create_trafficclassifier_traffic_class_list_by_id(const std::string &name, const std::vector<TrafficClassJsonObject> &value);
  void delete_trafficclassifier_by_id(const std::string &name);
  void delete_trafficclassifier_traffic_class_by_id(const std::string &name, const uint32_t &id);
  void delete_trafficclassifier_traffic_class_list_by_id(const std::string &name);
  TrafficclassifierJsonObject read_trafficclassifier_by_id(const std::string &name);
  std::vector<TrafficclassifierJsonObject> read_trafficclassifier_list_by_id();
  TrafficClassJsonObject read_trafficclassifier_traffic_class_by_id(const std::string &name, const uint32_t &id);
  std::string read_trafficclassifier_traffic_class_dmac_by_id(const std::string &name, const uint32_t &id);
  uint16_t read_trafficclassifier_traffic_class_dport_by_id(const std::string &name, const uint32_t &id);
  std::string read_trafficclassifier_traffic_class_dstip_by_id(const std::string &name, const uint32_t &id);
  TrafficClassEthtypeEnum read_trafficclassifier_traffic_class_ethtype_by_id(const std::string &name, const uint32_t &id);
  TrafficClassL4protoEnum read_trafficclassifier_traffic_class_l4proto_by_id(const std::string &name, const uint32_t &id);
  std::vector<TrafficClassJsonObject> read_trafficclassifier_traffic_class_list_by_id(const std::string &name);
  uint32_t read_trafficclassifier_traffic_class_priority_by_id(const std::string &name, const uint32_t &id);
  std::string read_trafficclassifier_traffic_class_smac_by_id(const std::string &name, const uint32_t &id);
  uint16_t read_trafficclassifier_traffic_class_sport_by_id(const std::string &name, const uint32_t &id);
  std::string read_trafficclassifier_traffic_class_srcip_by_id(const std::string &name, const uint32_t &id);
  void replace_trafficclassifier_by_id(const std::string &name, const TrafficclassifierJsonObject &value);
  void replace_trafficclassifier_traffic_class_by_id(const std::string &name, const uint32_t &id, const TrafficClassJsonObject &value);
  void replace_trafficclassifier_traffic_class_list_by_id(const std::string &name, const std::vector<TrafficClassJsonObject> &value);
  void update_trafficclassifier_by_id(const std::string &name, const TrafficclassifierJsonObject &value);
  void update_trafficclassifier_list_by_id(const std::vector<TrafficclassifierJsonObject> &value);
  void update_trafficclassifier_traffic_class_by_id(const std::string &name, const uint32_t &id, const TrafficClassJsonObject &value);
  void update_trafficclassifier_traffic_class_dmac_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_trafficclassifier_traffic_class_dport_by_id(const std::string &name, const uint32_t &id, const uint16_t &value);
  void update_trafficclassifier_traffic_class_dstip_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_trafficclassifier_traffic_class_ethtype_by_id(const std::string &name, const uint32_t &id, const TrafficClassEthtypeEnum &value);
  void update_trafficclassifier_traffic_class_l4proto_by_id(const std::string &name, const uint32_t &id, const TrafficClassL4protoEnum &value);
  void update_trafficclassifier_traffic_class_list_by_id(const std::string &name, const std::vector<TrafficClassJsonObject> &value);
  void update_trafficclassifier_traffic_class_priority_by_id(const std::string &name, const uint32_t &id, const uint32_t &value);
  void update_trafficclassifier_traffic_class_smac_by_id(const std::string &name, const uint32_t &id, const std::string &value);
  void update_trafficclassifier_traffic_class_sport_by_id(const std::string &name, const uint32_t &id, const uint16_t &value);
  void update_trafficclassifier_traffic_class_srcip_by_id(const std::string &name, const uint32_t &id, const std::string &value);

  /* help related */
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_trafficclassifier_list_by_id_get_list();
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_trafficclassifier_traffic_class_list_by_id_get_list(const std::string &name);

}
}
}
}
