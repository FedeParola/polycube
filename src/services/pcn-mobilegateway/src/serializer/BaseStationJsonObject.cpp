/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */



#include "BaseStationJsonObject.h"
#include <regex>

namespace polycube {
namespace service {
namespace model {

BaseStationJsonObject::BaseStationJsonObject() {
  m_ipIsSet = false;
}

BaseStationJsonObject::BaseStationJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_ipIsSet = false;


  if (val.count("ip")) {
    setIp(val.at("ip").get<std::string>());
  }
}

nlohmann::json BaseStationJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_ipIsSet) {
    val["ip"] = m_ip;
  }

  return val;
}

std::string BaseStationJsonObject::getIp() const {
  return m_ip;
}

void BaseStationJsonObject::setIp(std::string value) {
  m_ip = value;
  m_ipIsSet = true;
}

bool BaseStationJsonObject::ipIsSet() const {
  return m_ipIsSet;
}




}
}
}

