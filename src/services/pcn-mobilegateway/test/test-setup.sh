polycubectl mobilegateway add gw1

polycubectl gw1 ports add to_veth1 ip=10.0.1.254/24 peer=veth1
polycubectl gw1 ports add to_veth2 ip=10.0.2.254/24 peer=veth2
polycubectl gw1 ports add to_veth3 ip=10.0.3.254/24 peer=veth3
