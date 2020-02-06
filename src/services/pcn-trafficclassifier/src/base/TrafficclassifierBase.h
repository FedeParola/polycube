/**
* trafficclassifier API generated from trafficclassifier.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* TrafficclassifierBase.h
*
*
*/

#pragma once

#include "../serializer/TrafficclassifierJsonObject.h"

#include "../TrafficClass.h"

#include "polycube/services/transparent_cube.h"



#include "polycube/services/utils.h"
#include "polycube/services/fifo_map.hpp"

#include <spdlog/spdlog.h>

using namespace polycube::service::model;


class TrafficclassifierBase: public virtual polycube::service::TransparentCube {
 public:
  TrafficclassifierBase(const std::string name);
  
  virtual ~TrafficclassifierBase();
  virtual void update(const TrafficclassifierJsonObject &conf);
  virtual TrafficclassifierJsonObject toJsonObject();

  /// <summary>
  /// Traffic class identified by id
  /// </summary>
  virtual std::shared_ptr<TrafficClass> getTrafficClass(const uint32_t &id) = 0;
  virtual std::vector<std::shared_ptr<TrafficClass>> getTrafficClassList() = 0;
  virtual void addTrafficClass(const uint32_t &id, const TrafficClassJsonObject &conf) = 0;
  virtual void addTrafficClassList(const std::vector<TrafficClassJsonObject> &conf);
  virtual void replaceTrafficClass(const uint32_t &id, const TrafficClassJsonObject &conf);
  virtual void delTrafficClass(const uint32_t &id) = 0;
  virtual void delTrafficClassList();
};
