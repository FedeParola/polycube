/**
* mobilegateway API generated from mobilegateway.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


// TODO: Modify these methods with your own implementation


#include "ArpTable.h"
#include "Mobilegateway.h"


ArpTable::ArpTable(Mobilegateway &parent, const ArpTableJsonObject &conf)
    : ArpTableBase(parent) {
    logger()->info("Creating ArpTable instance");
}

ArpTable::ArpTable(Mobilegateway &parent, const std::string &mac,
                   const std::string &ip, const std::string &interface)
    : ArpTableBase(parent), mac_(mac), ip_(ip), interface_(interface) {}

ArpTable::~ArpTable() {}

std::string ArpTable::getAddress() {
  // This method retrieves the address value.
  return ip_;
}

std::string ArpTable::getMac() {
  // This method retrieves the mac value.
  return mac_;
}

void ArpTable::setMac(const std::string &value) {
  throw std::runtime_error("ArpTable::setMac: Method not implemented");
}

std::string ArpTable::getInterface() {
  // This method retrieves the interface value.
  return interface_;
}

void ArpTable::setInterface(const std::string &value) {
  throw std::runtime_error("ArpTable::setInterface: Method not implemented");
}


