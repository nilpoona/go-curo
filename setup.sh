#!/bin/bash

# create Network Namespace
sudo ip netns add router1
sudo ip netns add host1
sudo ip netns add host2
sudo ip netns ls

# created Network Namespace only has a Loopback interface so far.
# To connect each Network Namespace, you create a veth interface using the ip link add command.
sudo ip link add name host1-router1 type veth peer name router1-host1
sudo ip link add name host2-router1 type veth peer name router1-host2

# confirm
ip a

sudo ip link set host1-router1 netns host1
sudo ip link set router1-host1 netns router1
sudo ip link set host2-router1 netns host2
sudo ip link set router1-host2 netns router1

sudo ip netns exec host1 ip link set host1-router1 up
sudo ip netns exec router1 ip link set router1-host1 up
sudo ip netns exec host2 ip link set host2-router1 up
sudo ip netns exec router1 ip link set router1-host2 up

sudo ip netns exec host1 ip addr add 192.168.1.2/24 dev host1-router1
sudo ip netns exec host1 ip route add default via 192.168.1.1
sudo ip netns exec router1 ip addr add 192.168.1.1/24 dev router1-host1
sudo ip netns exec host2 ip addr add 192.168.0.2/24 dev host2-router1
sudo ip netns exec host2 ip route add default via 192.168.0.1
sudo ip netns exec router1 ip addr add 192.168.0.1/24 dev router1-host2

