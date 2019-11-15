/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/

#pragma once

#include "../base/RouteBase.h"

#include <linux/version.h>

#include "ArpTable.h"
#include "Ports.h"

#include "CircularBuffer.h"

#include <tins/ethernetII.h>

#include <tins/tins.h>

/* this define allow the code that required
   the kernel version 4.15 to work */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
#define NEW_KERNEL_VERS
#endif

// TODO: replace with an ENUM
#define TYPE_NOLOCALINTERFACE 0  // used to compare the 'type' field in the rt_v
#define TYPE_LOCALINTERFACE 1
#define TYPE_UE 2

class Mobilegateway;

using namespace polycube::service::model;

class Route : public RouteBase {
 public:
  Route(Mobilegateway &parent, const RouteJsonObject &conf);
  Route(Mobilegateway &parent, const std::string network, const std::string &nexthop,
        const std::string &interface, const uint32_t pathcost);
  virtual ~Route();

  /// <summary>
  /// Destination network IP
  /// </summary>
  std::string getNetwork() override;

  /// <summary>
  /// Next hop; if destination is local will be shown &#39;local&#39; instead of the ip address
  /// </summary>
  std::string getNexthop() override;

  /// <summary>
  /// Outgoing interface
  /// </summary>
  std::string getInterface() override;

  /// <summary>
  /// Cost of this route
  /// </summary>
  uint32_t getPathcost() override;
  void setPathcost(const uint32_t &value) override;

    // The following methods have been added manually
  bool pathcostIsSet();

 private:
  // The following attributes have been added manually
  std::string network_;
  std::string nexthop_;
  std::string interface_;
  uint32_t pathcost_;

  bool pathCostIsSet_;
};
