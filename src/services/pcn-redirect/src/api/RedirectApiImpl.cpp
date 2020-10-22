/**
* redirect API generated from redirect.yang
*
* NOTE: This file is auto generated by polycube-codegen
* https://github.com/polycube-network/polycube-codegen
*/


/* Do not edit this file manually */


#include "RedirectApiImpl.h"

namespace polycube {
namespace service {
namespace api {

using namespace polycube::service::model;

namespace RedirectApiImpl {
namespace {
std::unordered_map<std::string, std::shared_ptr<Redirect>> cubes;
std::mutex cubes_mutex;

std::shared_ptr<Redirect> get_cube(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  auto iter = cubes.find(name);
  if (iter == cubes.end()) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }

  return iter->second;
}

}

void create_redirect_by_id(const std::string &name, const RedirectJsonObject &jsonObject) {
  {
    // check if name is valid before creating it
    std::lock_guard<std::mutex> guard(cubes_mutex);
    if (cubes.count(name) != 0) {
      throw std::runtime_error("There is already a cube with name " + name);
    }
  }
  auto ptr = std::make_shared<Redirect>(name, jsonObject);
  std::unordered_map<std::string, std::shared_ptr<Redirect>>::iterator iter;
  bool inserted;

  std::lock_guard<std::mutex> guard(cubes_mutex);
  std::tie(iter, inserted) = cubes.emplace(name, std::move(ptr));

  if (!inserted) {
    throw std::runtime_error("There is already a cube with name " + name);
  }
}

void replace_redirect_by_id(const std::string &name, const RedirectJsonObject &bridge){
  throw std::runtime_error("Method not supported!");
}

void delete_redirect_by_id(const std::string &name) {
  std::lock_guard<std::mutex> guard(cubes_mutex);
  if (cubes.count(name) == 0) {
    throw std::runtime_error("Cube " + name + " does not exist");
  }
  cubes.erase(name);
}

std::vector<RedirectJsonObject> read_redirect_list_by_id() {
  std::vector<RedirectJsonObject> jsonObject_vect;
  for(auto &i : cubes) {
    auto m = get_cube(i.first);
    jsonObject_vect.push_back(m->toJsonObject());
  }
  return jsonObject_vect;
}

std::vector<nlohmann::fifo_map<std::string, std::string>> read_redirect_list_by_id_get_list() {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  for (auto &x : cubes) {
    nlohmann::fifo_map<std::string, std::string> m;
    m["name"] = x.first;
    r.push_back(std::move(m));
  }
  return r;
}

/**
* @brief   Create ports by ID
*
* Create operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
create_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value) {
  auto redirect = get_cube(name);

  return redirect->addPorts(portsName, value);
}

/**
* @brief   Create ports by ID
*
* Create operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
create_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value) {
  auto redirect = get_cube(name);
  redirect->addPortsList(value);
}

/**
* @brief   Delete ports by ID
*
* Delete operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
*
*/
void
delete_redirect_ports_by_id(const std::string &name, const std::string &portsName) {
  auto redirect = get_cube(name);

  return redirect->delPorts(portsName);
}

/**
* @brief   Delete ports by ID
*
* Delete operation of resource: ports*
*
* @param[in] name ID of name
*
* Responses:
*
*/
void
delete_redirect_ports_list_by_id(const std::string &name) {
  auto redirect = get_cube(name);
  redirect->delPortsList();
}

/**
* @brief   Read redirect by ID
*
* Read operation of resource: redirect*
*
* @param[in] name ID of name
*
* Responses:
* RedirectJsonObject
*/
RedirectJsonObject
read_redirect_by_id(const std::string &name) {
  return get_cube(name)->toJsonObject();

}

/**
* @brief   Read ports by ID
*
* Read operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
*
* Responses:
* PortsJsonObject
*/
PortsJsonObject
read_redirect_ports_by_id(const std::string &name, const std::string &portsName) {
  auto redirect = get_cube(name);
  return redirect->getPorts(portsName)->toJsonObject();

}

/**
* @brief   Read ports by ID
*
* Read operation of resource: ports*
*
* @param[in] name ID of name
*
* Responses:
* std::vector<PortsJsonObject>
*/
std::vector<PortsJsonObject>
read_redirect_ports_list_by_id(const std::string &name) {
  auto redirect = get_cube(name);
  auto &&ports = redirect->getPortsList();
  std::vector<PortsJsonObject> m;
  for(auto &i : ports)
    m.push_back(i->toJsonObject());
  return m;
}

/**
* @brief   Replace ports by ID
*
* Replace operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
replace_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value) {
  auto redirect = get_cube(name);

  return redirect->replacePorts(portsName, value);
}

/**
* @brief   Replace ports by ID
*
* Replace operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
replace_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}

/**
* @brief   Update redirect by ID
*
* Update operation of resource: redirect*
*
* @param[in] name ID of name
* @param[in] value redirectbody object
*
* Responses:
*
*/
void
update_redirect_by_id(const std::string &name, const RedirectJsonObject &value) {
  auto redirect = get_cube(name);

  return redirect->update(value);
}

/**
* @brief   Update redirect by ID
*
* Update operation of resource: redirect*
*
* @param[in] value redirectbody object
*
* Responses:
*
*/
void
update_redirect_list_by_id(const std::vector<RedirectJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}

/**
* @brief   Update ports by ID
*
* Update operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] portsName ID of ports_name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
update_redirect_ports_by_id(const std::string &name, const std::string &portsName, const PortsJsonObject &value) {
  auto redirect = get_cube(name);
  auto ports = redirect->getPorts(portsName);

  return ports->update(value);
}

/**
* @brief   Update ports by ID
*
* Update operation of resource: ports*
*
* @param[in] name ID of name
* @param[in] value portsbody object
*
* Responses:
*
*/
void
update_redirect_ports_list_by_id(const std::string &name, const std::vector<PortsJsonObject> &value) {
  throw std::runtime_error("Method not supported");
}



/*
 * help related
 */

std::vector<nlohmann::fifo_map<std::string, std::string>> read_redirect_ports_list_by_id_get_list(const std::string &name) {
  std::vector<nlohmann::fifo_map<std::string, std::string>> r;
  auto &&redirect = get_cube(name);

  auto &&ports = redirect->getPortsList();
  for(auto &i : ports) {
    nlohmann::fifo_map<std::string, std::string> keys;

    keys["name"] = i->getName();

    r.push_back(keys);
  }
  return r;
}


}

}
}
}
