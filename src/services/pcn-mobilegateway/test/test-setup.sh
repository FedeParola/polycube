#!/bin/bash 

LIBGTPNL=$HOME/libgtpnl/tools

set -x

# Remove all GTP links
sudo pkill gtp-link

# Create 2 namespaces for UEs and BSs
for i in `seq 1 2`;
do
    sudo ip netns del ns${i} > /dev/null 2>&1 # remove ns if already existed
    sudo ip link del veth${i} > /dev/null 2>&1

    sudo ip netns add ns${i}
    
    # Configure the UE
    sudo ip netns exec ns${i} ifconfig lo 172.99.0.${i}/32
    sudo ip netns exec ns${i} ip link set lo up
    
    # Configure the BS
    sudo ip link add veth${i}_ type veth peer name veth${i}
    sudo ip link set veth${i}_ netns ns${i}
    sudo ip netns exec ns${i} ip link set dev veth${i}_ up
    sudo ip link set dev veth${i} up
    sudo ip netns exec ns${i} ifconfig veth${i}_ 172.0.${i}.1/24
    
    # Configure the GTP tunnel
    sudo ip netns exec ns${i} $LIBGTPNL/gtp-link add gtp${i} --sgsn &
    sleep 1
    sudo ip netns exec ns${i} $LIBGTPNL/gtp-tunnel add gtp${i} v1 ${i}00 ${i}00 172.99.0.${i} 172.0.${i}.254
    sudo ip netns exec ns${i} route add default dev gtp${i}
done

# Create 2 namespaces for hosts on the external Packet Data Network
for i in `seq 3 4`;
do
    sudo ip netns del ns${i} > /dev/null 2>&1 # remove ns if already existed
    sudo ip link del veth${i} > /dev/null 2>&1

    sudo ip netns add ns${i}
    sudo ip link add veth${i}_ type veth peer name veth${i}
    sudo ip link set veth${i}_ netns ns${i}
    sudo ip netns exec ns${i} ip link set dev veth${i}_ up
    sudo ip link set dev veth${i} up
    sudo ip netns exec ns${i} ifconfig veth${i}_ 10.0.${i}.1/24
    sudo ip netns exec ns${i} route add default gw 10.0.${i}.254 veth${i}_
done

polycubectl mobilegateway add mgw1

# Add UE ports
polycubectl mgw1 ports add port1 peer=veth1 direction=UE ip=172.0.1.254/24
polycubectl mgw1 ports add port2 peer=veth2 direction=UE ip=172.0.2.254/24

# Add PDN ports
polycubectl mgw1 ports add port3 peer=veth3 ip=10.0.3.254/24
polycubectl mgw1 ports add port4 peer=veth4 ip=10.0.4.254/24

# Add BSs
polycubectl mgw1 base-station add 172.0.1.1
polycubectl mgw1 base-station add 172.0.2.1

# Add UEs
polycubectl mgw1 user-equipment add 172.99.0.1 tunnel-endpoint=172.0.1.1 teid=100  rate-limit=100000
polycubectl mgw1 user-equipment add 172.99.0.2 tunnel-endpoint=172.0.2.1 teid=200
