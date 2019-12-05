/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* UserEquipmentJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace polycube {
namespace service {
namespace model {


/// <summary>
///
/// </summary>
class  UserEquipmentJsonObject : public JsonObjectBase {
public:
  UserEquipmentJsonObject();
  UserEquipmentJsonObject(const nlohmann::json &json);
  ~UserEquipmentJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// IP address of the User Equipment
  /// </summary>
  std::string getIp() const;
  void setIp(std::string value);
  bool ipIsSet() const;

  /// <summary>
  /// IP address of the Base Station that connects the User Equipment
  /// </summary>
  std::string getTunnelEndpoint() const;
  void setTunnelEndpoint(std::string value);
  bool tunnelEndpointIsSet() const;

  /// <summary>
  /// Tunnel Endpoint ID of the GTP tunnel used by the User Equipment
  /// </summary>
  uint32_t getTeid() const;
  void setTeid(uint32_t value);
  bool teidIsSet() const;

  /// <summary>
  /// Rate limit for the traffic exchanged by the User Equipment (in bps)
  /// </summary>
  uint32_t getRateLimit() const;
  void setRateLimit(uint32_t value);
  bool rateLimitIsSet() const;
  void unsetRateLimit();

private:
  std::string m_ip;
  bool m_ipIsSet;
  std::string m_tunnelEndpoint;
  bool m_tunnelEndpointIsSet;
  uint32_t m_teid;
  bool m_teidIsSet;
  uint32_t m_rateLimit;
  bool m_rateLimitIsSet;
};

}
}
}

