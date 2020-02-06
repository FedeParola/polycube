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

#include "Trafficclassifier.h"
#include "../modules/ExactMatcher.h"
#include "../modules/Parser.h"
#include "../modules/PrefixMatcher.h"
#include "../modules/Selector.h"
#include "../modules/Tagger.h"

using namespace polycube::service::utils;

Trafficclassifier::Trafficclassifier(const std::string name,
                                     const TrafficclassifierJsonObject &conf)
    : TransparentCube(conf.getBase(), {}, {}),
      TrafficclassifierBase(name),
      active_pipeline_(1) {
  logger()->info("Creating Trafficclassifier instance");

  programs_[PROG_INDEX(SELECTOR)] =
      std::dynamic_pointer_cast<Program>(std::make_shared<Selector>(*this));

  programs_[PROG_INDEX(PARSER)] =
      std::dynamic_pointer_cast<Program>(std::make_shared<Parser>(*this));

  programs_[PROG_INDEX(SMAC)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint64_t>>(*this, SMAC));

  programs_[PROG_INDEX(DMAC)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint64_t>>(*this, DMAC));

  programs_[PROG_INDEX(ETHTYPE)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint16_t>>(*this, ETHTYPE));

  programs_[PROG_INDEX(SRCIP)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<PrefixMatcher<uint32_t>>(*this, SRCIP));

  programs_[PROG_INDEX(DSTIP)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<PrefixMatcher<uint32_t>>(*this, DSTIP));

  programs_[PROG_INDEX(L4PROTO)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint8_t>>(*this, L4PROTO));

  programs_[PROG_INDEX(SPORT)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint16_t>>(*this, SPORT));

  programs_[PROG_INDEX(DPORT)] = std::dynamic_pointer_cast<Program>(
      std::make_shared<ExactMatcher<uint16_t>>(*this, DPORT));

  programs_[PROG_INDEX(TAGGER)] =
      std::dynamic_pointer_cast<Program>(std::make_shared<Tagger>(*this));

  logger()->debug("Classification pipeline created");

  std::dynamic_pointer_cast<Selector>(programs_[PROG_INDEX(SELECTOR)])->load();

  addTrafficClassList(conf.getTrafficClass());
}

Trafficclassifier::~Trafficclassifier() {
  logger()->info("Destroying Trafficclassifier instance");
}

void Trafficclassifier::packet_in(polycube::service::Direction direction,
                                  polycube::service::PacketInMetadata &md,
                                  const std::vector<uint8_t> &packet) {
  logger()->debug("Packet received");
}

std::shared_ptr<TrafficClass> Trafficclassifier::getTrafficClass(
    const uint32_t &id) {
  if (traffic_classes_.count(id) == 0) {
    throw std::runtime_error("No traffic class with the given id");
  }

  return traffic_classes_.at(id);
}

std::vector<std::shared_ptr<TrafficClass>>
Trafficclassifier::getTrafficClassList() {
  std::vector<std::shared_ptr<TrafficClass>> traffic_classes_v;

  traffic_classes_v.reserve(traffic_classes_.size());

  for (auto const &entry : traffic_classes_) {
    traffic_classes_v.push_back(entry.second);
  }

  return traffic_classes_v;
}

void Trafficclassifier::addTrafficClass(const uint32_t &id,
                                        const TrafficClassJsonObject &conf) {
  if (traffic_classes_.count(id) != 0) {
    throw std::runtime_error("Traffic class with the given id already exists");
  }

  if (traffic_classes_.size() == MAX_TRAFFIC_CLASSES) {
    throw std::runtime_error("Maximum number of traffic classes reached");
  }

  traffic_classes_[id] = std::make_shared<TrafficClass>(*this, conf);

  updateClassificationPipeline();
}

void Trafficclassifier::addTrafficClassList(
    const std::vector<TrafficClassJsonObject> &conf) {
  if (conf.size() == 0) {
    return;
  }

  if (traffic_classes_.size() + conf.size() > MAX_TRAFFIC_CLASSES) {
    throw std::runtime_error("Maximum number of traffic classes reached");
  }

  for (auto &it : conf) {
    if (traffic_classes_.count(it.getId()) != 0) {
      throw std::runtime_error(std::string("Traffic class with id ") +
                               std::to_string(it.getId()) + " already exists");
    }
  }

  for (auto &it : conf) {
    traffic_classes_[it.getId()] = std::make_shared<TrafficClass>(*this, it);
  }

  updateClassificationPipeline();
}

void Trafficclassifier::replaceTrafficClass(
    const uint32_t &id, const TrafficClassJsonObject &conf) {
  if (traffic_classes_.count(id) == 0) {
    throw std::runtime_error("No traffic class with the given id");
  }

  traffic_classes_[id] = std::make_shared<TrafficClass>(*this, conf);

  updateClassificationPipeline();
}

void Trafficclassifier::delTrafficClass(const uint32_t &id) {
  if (traffic_classes_.count(id) == 0) {
    throw std::runtime_error("No traffic class with the given id");
  }

  traffic_classes_.erase(id);

  updateClassificationPipeline();
}

void Trafficclassifier::delTrafficClassList() {
  traffic_classes_.clear();

  updateClassificationPipeline();
}

void Trafficclassifier::updateClassificationPipeline() {
  std::shared_ptr<Selector> selector =
      std::dynamic_pointer_cast<Selector>(programs_[PROG_INDEX(SELECTOR)]);

  if (traffic_classes_.size() == 0) {
    // No classes, disable classification
    selector->setClassificationEnabled(false);
    selector->load();

    logger()->debug("Classification disabled");

    return;
  }

  std::array<bool, PROGRAMS_COUNT> needed_programs;

  for (int i = PROG_INDEX(PARSER); i <= PROG_INDEX(TAGGER); i++) {
    if (i == PROG_INDEX(PARSER) || i == PROG_INDEX(TAGGER)) {
      needed_programs[i] = true;
    } else {
      needed_programs[i] = false;
    }

    programs_[i]->initBitvector(traffic_classes_.size());
  }

  // Compute bitvectors

  std::vector<std::shared_ptr<TrafficClass>> classes = getTrafficClassList();

  // Sort by priority in decreasing order
  std::sort(classes.begin(), classes.end(),
            [](std::shared_ptr<TrafficClass> c1,
               std::shared_ptr<TrafficClass> c2) { return !(*c1 < *c2); });

  std::shared_ptr<Tagger> tagger =
      std::dynamic_pointer_cast<Tagger>(programs_[PROG_INDEX(TAGGER)]);

  for (auto c : classes) {
    tagger->appendClassId(c->getId());

    bool need_ip = false;
    bool need_tcp_udp = false;

    // sport
    {
      std::shared_ptr<ExactMatcher<uint16_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint16_t>>(
              programs_[PROG_INDEX(SPORT)]);

      if (c->sportIsSet()) {
        m->appendValueBit(htons(c->getSport()));
        needed_programs[PROG_INDEX(SPORT)] = true;
        need_tcp_udp = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // dport
    {
      std::shared_ptr<ExactMatcher<uint16_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint16_t>>(
              programs_[PROG_INDEX(DPORT)]);

      if (c->dportIsSet()) {
        m->appendValueBit(htons(c->getDport()));
        needed_programs[PROG_INDEX(DPORT)] = true;
        need_tcp_udp = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // l4proto
    {
      std::shared_ptr<ExactMatcher<uint8_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint8_t>>(
              programs_[PROG_INDEX(L4PROTO)]);

      if (c->l4protoIsSet()) {
        m->appendValueBit(kL4protos[static_cast<int>(c->getL4proto())]);
        needed_programs[PROG_INDEX(L4PROTO)] = true;
        need_ip = true;

      } else if (need_tcp_udp) {
        m->appendValuesBit({IPPROTO_TCP, IPPROTO_UDP});
        needed_programs[PROG_INDEX(L4PROTO)] = true;
        need_ip = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // srcip
    {
      std::shared_ptr<PrefixMatcher<uint32_t>> m =
          std::dynamic_pointer_cast<PrefixMatcher<uint32_t>>(
              programs_[PROG_INDEX(SRCIP)]);

      if (c->srcipIsSet()) {
        m->appendValueBit(ip_string_to_nbo_uint(c->getSrcip()),
                          std::stoi(get_netmask_from_string(c->getSrcip())));
        needed_programs[PROG_INDEX(SRCIP)] = true;
        need_ip = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // dstip
    {
      std::shared_ptr<PrefixMatcher<uint32_t>> m =
          std::dynamic_pointer_cast<PrefixMatcher<uint32_t>>(
              programs_[PROG_INDEX(DSTIP)]);

      if (c->dstipIsSet()) {
        m->appendValueBit(ip_string_to_nbo_uint(c->getDstip()),
                          std::stoi(get_netmask_from_string(c->getDstip())));
        needed_programs[PROG_INDEX(DSTIP)] = true;
        need_ip = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // ethtype
    {
      std::shared_ptr<ExactMatcher<uint16_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint16_t>>(
              programs_[PROG_INDEX(ETHTYPE)]);

      if (c->ethtypeIsSet()) {
        m->appendValueBit(htons(kEthtypes[static_cast<int>(c->getL4proto())]));
        needed_programs[PROG_INDEX(ETHTYPE)] = true;

      } else if (need_ip) {
        m->appendValueBit(htons(ETH_P_IP));
        needed_programs[PROG_INDEX(ETHTYPE)] = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // smac
    {
      std::shared_ptr<ExactMatcher<uint64_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint64_t>>(
              programs_[PROG_INDEX(SMAC)]);

      if (c->smacIsSet()) {
        m->appendValueBit(mac_string_to_nbo_uint(c->getSmac()));
        needed_programs[PROG_INDEX(SMAC)] = true;

      } else {
        m->appendWildcardBit();
      }
    }

    // dmac
    {
      std::shared_ptr<ExactMatcher<uint64_t>> m =
          std::dynamic_pointer_cast<ExactMatcher<uint64_t>>(
              programs_[PROG_INDEX(DMAC)]);

      if (c->dmacIsSet()) {
        m->appendValueBit(mac_string_to_nbo_uint(c->getDmac()));
        needed_programs[PROG_INDEX(DMAC)] = true;

      } else {
        m->appendWildcardBit();
      }
    }
  }

  logger()->debug("Bitvectors computed");

  // Switch the classification pipeline
  active_pipeline_ = (active_pipeline_ + 1) % 2;

  // Load programs starting from the end of the pipeline
  programs_[PROG_INDEX(TAGGER)]->load(active_pipeline_);
  logger()->debug("Program TAGGER loaded");

  int next = PROG_INDEX(TAGGER);
  for (int i = PROG_INDEX(TAGGER) - 1; i >= PROG_INDEX(PARSER); i--) {
    if (needed_programs[i]) {
      programs_[i]->setNext(next + active_pipeline_ * (PROGRAMS_COUNT - 1));
      next = i;
      programs_[i]->load(active_pipeline_);
      logger()->debug("Program {0} loaded", i);
    }
  }

  selector->setNext(PROG_INDEX(PARSER, active_pipeline_));
  selector->setClassificationEnabled(true);
  selector->load();

  logger()->debug("Classification pipeline updated");
}