/**
* policer API generated from policer.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */



#include "ContractJsonObject.h"
#include <regex>

namespace polycube {
namespace service {
namespace model {

ContractJsonObject::ContractJsonObject() {
  m_trafficClassIsSet = false;
  m_actionIsSet = false;
  m_rateLimitIsSet = false;
  m_burstLimitIsSet = false;
}

ContractJsonObject::ContractJsonObject(const nlohmann::json &val) :
  JsonObjectBase(val) {
  m_trafficClassIsSet = false;
  m_actionIsSet = false;
  m_rateLimitIsSet = false;
  m_burstLimitIsSet = false;


  if (val.count("traffic-class")) {
    setTrafficClass(val.at("traffic-class").get<uint32_t>());
  }

  if (val.count("action")) {
    setAction(string_to_ActionTypeEnum(val.at("action").get<std::string>()));
  }

  if (val.count("rate-limit")) {
    setRateLimit(val.at("rate-limit").get<uint64_t>());
  }

  if (val.count("burst-limit")) {
    setBurstLimit(val.at("burst-limit").get<uint64_t>());
  }
}

nlohmann::json ContractJsonObject::toJson() const {
  nlohmann::json val = nlohmann::json::object();
  if (!getBase().is_null()) {
    val.update(getBase());
  }

  if (m_trafficClassIsSet) {
    val["traffic-class"] = m_trafficClass;
  }

  if (m_actionIsSet) {
    val["action"] = ActionTypeEnum_to_string(m_action);
  }

  if (m_rateLimitIsSet) {
    val["rate-limit"] = m_rateLimit;
  }

  if (m_burstLimitIsSet) {
    val["burst-limit"] = m_burstLimit;
  }

  return val;
}

uint32_t ContractJsonObject::getTrafficClass() const {
  return m_trafficClass;
}

void ContractJsonObject::setTrafficClass(uint32_t value) {
  m_trafficClass = value;
  m_trafficClassIsSet = true;
}

bool ContractJsonObject::trafficClassIsSet() const {
  return m_trafficClassIsSet;
}



ActionTypeEnum ContractJsonObject::getAction() const {
  return m_action;
}

void ContractJsonObject::setAction(ActionTypeEnum value) {
  m_action = value;
  m_actionIsSet = true;
}

bool ContractJsonObject::actionIsSet() const {
  return m_actionIsSet;
}



std::string ContractJsonObject::ActionTypeEnum_to_string(const ActionTypeEnum &value){
  switch(value) {
    case ActionTypeEnum::PASS:
      return std::string("pass");
    case ActionTypeEnum::LIMIT:
      return std::string("limit");
    case ActionTypeEnum::DROP:
      return std::string("drop");
    default:
      throw std::runtime_error("Bad Contract action");
  }
}

ActionTypeEnum ContractJsonObject::string_to_ActionTypeEnum(const std::string &str){
  if (JsonObjectBase::iequals("pass", str))
    return ActionTypeEnum::PASS;
  if (JsonObjectBase::iequals("limit", str))
    return ActionTypeEnum::LIMIT;
  if (JsonObjectBase::iequals("drop", str))
    return ActionTypeEnum::DROP;
  throw std::runtime_error("Contract action is invalid");
}
uint64_t ContractJsonObject::getRateLimit() const {
  return m_rateLimit;
}

void ContractJsonObject::setRateLimit(uint64_t value) {
  m_rateLimit = value;
  m_rateLimitIsSet = true;
}

bool ContractJsonObject::rateLimitIsSet() const {
  return m_rateLimitIsSet;
}

void ContractJsonObject::unsetRateLimit() {
  m_rateLimitIsSet = false;
}

uint64_t ContractJsonObject::getBurstLimit() const {
  return m_burstLimit;
}

void ContractJsonObject::setBurstLimit(uint64_t value) {
  m_burstLimit = value;
  m_burstLimitIsSet = true;
}

bool ContractJsonObject::burstLimitIsSet() const {
  return m_burstLimitIsSet;
}

void ContractJsonObject::unsetBurstLimit() {
  m_burstLimitIsSet = false;
}


}
}
}

