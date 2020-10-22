/**
* redirect API generated from redirect.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* RedirectApiImpl.h
*
*
*/

#pragma once


#include <memory>
#include <map>
#include <mutex>
#include "../Redirect.h"

#include "PortsJsonObject.h"
#include "RedirectJsonObject.h"
#include <vector>

namespace polycube {
namespace service {
namespace api {

using namespace polycube::service::model;

namespace RedirectApiImpl {
  void create_redirect_by_id(const std::string &name, const RedirectJsonObject &value);
  void create_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void create_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void delete_redirect_by_id(const std::string &name);
  void delete_redirect_ports_by_id(const std::string &name, const std::string &portsName);
  void delete_redirect_ports_list_by_id(const std::string &name);
  RedirectJsonObject read_redirect_by_id(const std::string &name);
  std::vector<RedirectJsonObject> read_redirect_list_by_id();
  PortsJsonObject read_redirect_ports_by_id(const std::string &name, const std::string &portsName);
  std::vector<PortsJsonObject> read_redirect_ports_list_by_id(const std::string &name);
  void replace_redirect_by_id(const std::string &name, const RedirectJsonObject &value);
  void replace_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void replace_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);
  void update_redirect_by_id(const std::string &name, const RedirectJsonObject &value);
  void update_redirect_list_by_id(const std::vector<RedirectJsonObject> &value);
  void update_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value);
  void update_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value);

  /* help related */
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_redirect_list_by_id_get_list();
  std::vector<nlohmann::fifo_map<std::string, std::string>> read_redirect_ports_list_by_id_get_list(const std::string &name);

}
}
}
}

