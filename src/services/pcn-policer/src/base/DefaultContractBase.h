/**
* policer API generated from policer.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */

/*
* DefaultContractBase.h
*
*
*/

#pragma once

#include "../serializer/DefaultContractJsonObject.h"

#include "../serializer/DefaultContractUpdateDataInputJsonObject.h"






#include <spdlog/spdlog.h>

using namespace polycube::service::model;

class Policer;

class DefaultContractBase {
 public:
  
  DefaultContractBase(Policer &parent);
  
  virtual ~DefaultContractBase();
  virtual void update(const DefaultContractJsonObject &conf);
  virtual DefaultContractJsonObject toJsonObject();

  /// <summary>
  /// Action applied to traffic of the contract: PASS &#x3D; Let all the traffic pass without limitations; LIMIT &#x3D; Apply rate limit to selected traffic; DROP &#x3D; Drop all the traffic
  /// </summary>
  virtual ActionTypeEnum getAction() = 0;

  /// <summary>
  /// Maximum average traffic rate (in kbit/s)
  /// </summary>
  virtual uint64_t getRateLimit() = 0;
  virtual void updateData(DefaultContractUpdateDataInputJsonObject input) = 0;

  std::shared_ptr<spdlog::logger> logger();
 protected:
  Policer &parent_;
};
