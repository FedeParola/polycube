/**
* redirect API generated from redirect.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


// TODO: Modify these methods with your own implementation


#include "Redirect.h"
#include "Redirect_dp.h"

Redirect::Redirect(const std::string name, const RedirectJsonObject &conf)
  : Cube(conf.getBase(), { redirect_code }, {}),
    RedirectBase(name) {
  logger()->info("Creating Redirect instance");
  addPortsList(conf.getPorts());
}


Redirect::~Redirect() {
  logger()->info("Destroying Redirect instance");
}

void Redirect::packet_in(Ports &port,
    polycube::service::PacketInMetadata &md,
    const std::vector<uint8_t> &packet) {
  logger()->debug("Packet received from port {0}", port.name());
}

// Basic default implementation, place your extension here (if needed)
std::shared_ptr<Ports> Redirect::getPorts(const std::string &name) {
  // call default implementation in base class
  return RedirectBase::getPorts(name);
}

// Basic default implementation, place your extension here (if needed)
std::vector<std::shared_ptr<Ports>> Redirect::getPortsList() {
  // call default implementation in base class
  return RedirectBase::getPortsList();
}

// Basic default implementation, place your extension here (if needed)
void Redirect::addPorts(const std::string &name, const PortsJsonObject &conf) {
  RedirectBase::addPorts(name, conf);
}

// Basic default implementation, place your extension here (if needed)
void Redirect::addPortsList(const std::vector<PortsJsonObject> &conf) {
  // call default implementation in base class
  RedirectBase::addPortsList(conf);
}

// Basic default implementation, place your extension here (if needed)
void Redirect::replacePorts(const std::string &name, const PortsJsonObject &conf) {
  // call default implementation in base class
  RedirectBase::replacePorts(name, conf);
}

// Basic default implementation, place your extension here (if needed)
void Redirect::delPorts(const std::string &name) {
  // call default implementation in base class
  RedirectBase::delPorts(name);
}

// Basic default implementation, place your extension here (if needed)
void Redirect::delPortsList() {
  // call default implementation in base class
  RedirectBase::delPortsList();
}


