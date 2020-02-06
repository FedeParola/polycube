/**
* trafficclassifier API generated from trafficclassifier.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* TrafficClassJsonObject.h
*
*
*/

#pragma once


#include "JsonObjectBase.h"


namespace polycube {
namespace service {
namespace model {

enum class TrafficClassEthtypeEnum {
  ARP, IP
};
enum class TrafficClassL4protoEnum {
  ICMP, TCP, UDP
};

/// <summary>
///
/// </summary>
class  TrafficClassJsonObject : public JsonObjectBase {
public:
  TrafficClassJsonObject();
  TrafficClassJsonObject(const nlohmann::json &json);
  ~TrafficClassJsonObject() final = default;
  nlohmann::json toJson() const final;


  /// <summary>
  /// Id of the class, set in metadata of matching packets
  /// </summary>
  uint32_t getId() const;
  void setId(uint32_t value);
  bool idIsSet() const;

  /// <summary>
  /// Packets matching multiple classes are assigned to the one with highest priority
  /// </summary>
  uint32_t getPriority() const;
  void setPriority(uint32_t value);
  bool priorityIsSet() const;

  /// <summary>
  /// Source MAC address of the packet
  /// </summary>
  std::string getSmac() const;
  void setSmac(std::string value);
  bool smacIsSet() const;
  void unsetSmac();

  /// <summary>
  /// Destination MAC address of the packet
  /// </summary>
  std::string getDmac() const;
  void setDmac(std::string value);
  bool dmacIsSet() const;
  void unsetDmac();

  /// <summary>
  /// Ethertype of the packet (ARP | IP)
  /// </summary>
  TrafficClassEthtypeEnum getEthtype() const;
  void setEthtype(TrafficClassEthtypeEnum value);
  bool ethtypeIsSet() const;
  void unsetEthtype();
  static std::string TrafficClassEthtypeEnum_to_string(const TrafficClassEthtypeEnum &value);
  static TrafficClassEthtypeEnum string_to_TrafficClassEthtypeEnum(const std::string &str);

  /// <summary>
  /// Source IP address prefix of the packet
  /// </summary>
  std::string getSrcip() const;
  void setSrcip(std::string value);
  bool srcipIsSet() const;
  void unsetSrcip();

  /// <summary>
  /// Destination IP address prefix of the packet
  /// </summary>
  std::string getDstip() const;
  void setDstip(std::string value);
  bool dstipIsSet() const;
  void unsetDstip();

  /// <summary>
  /// Level 4 protocol of the packet (ICMP | TCP | UDP)
  /// </summary>
  TrafficClassL4protoEnum getL4proto() const;
  void setL4proto(TrafficClassL4protoEnum value);
  bool l4protoIsSet() const;
  void unsetL4proto();
  static std::string TrafficClassL4protoEnum_to_string(const TrafficClassL4protoEnum &value);
  static TrafficClassL4protoEnum string_to_TrafficClassL4protoEnum(const std::string &str);

  /// <summary>
  /// Source port of the packet
  /// </summary>
  uint16_t getSport() const;
  void setSport(uint16_t value);
  bool sportIsSet() const;
  void unsetSport();

  /// <summary>
  /// Destination port of the packet
  /// </summary>
  uint16_t getDport() const;
  void setDport(uint16_t value);
  bool dportIsSet() const;
  void unsetDport();

private:
  uint32_t m_id;
  bool m_idIsSet;
  uint32_t m_priority;
  bool m_priorityIsSet;
  std::string m_smac;
  bool m_smacIsSet;
  std::string m_dmac;
  bool m_dmacIsSet;
  TrafficClassEthtypeEnum m_ethtype;
  bool m_ethtypeIsSet;
  std::string m_srcip;
  bool m_srcipIsSet;
  std::string m_dstip;
  bool m_dstipIsSet;
  TrafficClassL4protoEnum m_l4proto;
  bool m_l4protoIsSet;
  uint16_t m_sport;
  bool m_sportIsSet;
  uint16_t m_dport;
  bool m_dportIsSet;
};

}
}
}
