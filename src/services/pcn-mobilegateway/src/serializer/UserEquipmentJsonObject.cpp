/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */



#include "UserEquipmentJsonObject.h"
#include <regex>

namespace polycube {
namespace service {
namespace model {

UserEquipmentJsonObject::UserEquipmentJsonObject() {
  m_ipIsSet = false;
  m_tunnelEndpointIsSet = false;
  m_teidIsSet = false;
  m_rateLimitIsSet = false;
}

UserEquipmentJsonObject::UserEquipmentJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_ipIsSet = false;
  m_tunnelEndpointIsSet = false;
  m_teidIsSet = false;
  m_rateLimitIsSet = false;


  if (val.count("ip")) {
    setIp(val.at("ip").get<std::string>());
  }

  if (val.count("tunnel-endpoint")) {
    setTunnelEndpoint(val.at("tunnel-endpoint").get<std::string>());
  }

  if (val.count("teid")) {
    setTeid(val.at("teid").get<uint32_t>());
  }

  if (val.count("rate-limit")) {
    setRateLimit(val.at("rate-limit").get<uint64_t>());
  }
}

nlohmann::json UserEquipmentJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_ipIsSet) {
    val["ip"] = m_ip;
  }

  if (m_tunnelEndpointIsSet) {
    val["tunnel-endpoint"] = m_tunnelEndpoint;
  }

  if (m_teidIsSet) {
    val["teid"] = m_teid;
  }

  if (m_rateLimitIsSet) {
    val["rate-limit"] = m_rateLimit;
  }

  return val;
}

std::string UserEquipmentJsonObject::getIp() const {
  return m_ip;
}

void UserEquipmentJsonObject::setIp(std::string value) {
  m_ip = value;
  m_ipIsSet = true;
}

bool UserEquipmentJsonObject::ipIsSet() const {
  return m_ipIsSet;
}



std::string UserEquipmentJsonObject::getTunnelEndpoint() const {
  return m_tunnelEndpoint;
}

void UserEquipmentJsonObject::setTunnelEndpoint(std::string value) {
  m_tunnelEndpoint = value;
  m_tunnelEndpointIsSet = true;
}

bool UserEquipmentJsonObject::tunnelEndpointIsSet() const {
  return m_tunnelEndpointIsSet;
}



uint32_t UserEquipmentJsonObject::getTeid() const {
  return m_teid;
}

void UserEquipmentJsonObject::setTeid(uint32_t value) {
  m_teid = value;
  m_teidIsSet = true;
}

bool UserEquipmentJsonObject::teidIsSet() const {
  return m_teidIsSet;
}



uint64_t UserEquipmentJsonObject::getRateLimit() const {
  return m_rateLimit;
}

void UserEquipmentJsonObject::setRateLimit(uint64_t value) {
  m_rateLimit = value;
  m_rateLimitIsSet = true;
}

bool UserEquipmentJsonObject::rateLimitIsSet() const {
  return m_rateLimitIsSet;
}

void UserEquipmentJsonObject::unsetRateLimit() {
  m_rateLimitIsSet = false;
}


}
}
}

