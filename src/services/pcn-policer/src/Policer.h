/*
 * Copyright 2020 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "../base/PolicerBase.h"
#include "Contract.h"
#include "DefaultContract.h"

#define MAX_CONTRACTS 100000

struct contract {
  uint8_t action;
  int64_t counter;  // Counter of bits that can still be forwarded in the
                    // current window
};

using namespace polycube::service::model;

class Policer : public PolicerBase {
 public:
  Policer(const std::string name, const PolicerJsonObject &conf);
  ~Policer();

  void packet_in(polycube::service::Direction direction,
                 polycube::service::PacketInMetadata &md,
                 const std::vector<uint8_t> &packet) override;

  /// <summary>
  /// Contract applied to traffic not matching any of the specified classes (default: PASS)
  /// </summary>
  std::shared_ptr<DefaultContract> getDefaultContract() override;
  void addDefaultContract(const DefaultContractJsonObject &value) override;
  void replaceDefaultContract(const DefaultContractJsonObject &conf) override;
  void delDefaultContract() override;

  /// <summary>
  /// Contract applied to a specific class of traffic
  /// </summary>
  std::shared_ptr<Contract> getContract(const uint32_t &trafficClass) override;
  std::vector<std::shared_ptr<Contract>> getContractList() override;
  void addContract(const uint32_t &trafficClass,
                   const ContractJsonObject &conf) override;
  void addContractList(const std::vector<ContractJsonObject> &conf) override;
  void replaceContract(const uint32_t &trafficClass,
                       const ContractJsonObject &conf) override;
  void delContract(const uint32_t &trafficClass) override;
  void delContractList() override;

 private:
  std::shared_ptr<DefaultContract> default_contract_;
  std::unordered_map<uint32_t, std::shared_ptr<Contract>> contracts_;

  // Thread to refill buckets
  std::thread buckets_refill_thread_;
  std::atomic<bool> quit_thread_;
  // Mutex to access contracts
  std::mutex contracts_mutex_;

  void refillBuckets();
};
