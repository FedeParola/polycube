/**
* policer API generated from policer.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* ContractJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace polycube {
namespace service {
namespace model {

#ifndef ACTIONTYPEENUM
#define ACTIONTYPEENUM
enum class ActionTypeEnum {
  PASS, LIMIT, DROP
};
#endif

/// <summary>
///
/// </summary>
class  ContractJsonObject : public JsonObjectBase {
public:
  ContractJsonObject();
  ContractJsonObject(const nlohmann::json &json);
  ~ContractJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Identifier of the class of traffic, provided as packet metadata
  /// </summary>
  uint32_t getTrafficClass() const;
  void setTrafficClass(uint32_t value);
  bool trafficClassIsSet() const;

  /// <summary>
  /// Action applied to traffic of the contract: PASS &#x3D; Let all the traffic pass without limitations; LIMIT &#x3D; Apply rate and burst limits to selected traffic; DROP &#x3D; Drop all the traffic
  /// </summary>
  ActionTypeEnum getAction() const;
  void setAction(ActionTypeEnum value);
  bool actionIsSet() const;
  static std::string ActionTypeEnum_to_string(const ActionTypeEnum &value);
  static ActionTypeEnum string_to_ActionTypeEnum(const std::string &str);

  /// <summary>
  /// Maximum average traffic rate (in kbit/s)
  /// </summary>
  uint64_t getRateLimit() const;
  void setRateLimit(uint64_t value);
  bool rateLimitIsSet() const;
  void unsetRateLimit();

  /// <summary>
  /// Maximum size of a burst of packets (in kbits)
  /// </summary>
  uint64_t getBurstLimit() const;
  void setBurstLimit(uint64_t value);
  bool burstLimitIsSet() const;
  void unsetBurstLimit();

private:
  uint32_t m_trafficClass;
  bool m_trafficClassIsSet;
  ActionTypeEnum m_action;
  bool m_actionIsSet;
  uint64_t m_rateLimit;
  bool m_rateLimitIsSet;
  uint64_t m_burstLimit;
  bool m_burstLimitIsSet;
};

}
}
}
