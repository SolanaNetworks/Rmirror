# RMIRROR
Rmirror is a Linux kernel module and iptables extension that mirrors 
traffic over a GRE tunnel. By implementing a new iptables RMIRROR target, 
the traffic can easily be configured and filtered for the mirror
without changing the original traffic.

Packets are then encapsulated in the GRE Tunnel and sent to a specified
destination IP addess. Rmirror is similar in behavior to Cisco's ERSPAN
capability but mirrors traffic throught Transparent Ethernet Bridging.

Rmirror is developed by Solana Networks. 
Thanks to ExtraHop for sponsoring this effort.

# Installing
install the dkms and iptables-dev packages

## Kernel Module
Installs with DKMS

Linux headers for your kernel version are required

 * Copy contents from rmirror/kmod to /usr/src/xt_rmirror-1
 * sudo dkms add -m xt_rmirror -v 1
 * sudo dkms build -m xt_rmirror -v 1
 * sudo dkms install -m xt_rmirror -v 1

## Iptables Addon
build and install addon for iptables

iptables-dev or iptables-devel (depending on linux distro) is required to compile iptables extensions

 * cd into rmirror/umod directory
 * Run 'make libxt_RMIRROR.so'
 * copy libxt_RMIRROR.so into /lib/xtables
 * test by running iptables -j RMIRROR -h, you will see a help message for the RMIRROR target at the bottom of the output

# Running
To view counters for rules: 

    sudo iptables -L -v

To catch all traffic coming into your system:

    sudo iptables -I INPUT -j RMIRROR --target <rmirrorip>

To trim the packet to 60 Bytes:

    sudo iptables -I INPUT -j RMIRROR --target <rmirrorip> --len <bytes>

To catch packets coming from a specific source IP:

    sudo iptables -I INPUT -s <sourceip> -j RMIRROR --target <rmirrorip>

To catch packets outgoing to a specific IP:

    sudo iptables -I OUTPUT -d <destip> -j RMIRROR --target <rmirrorip>

To catch packets coming from a specific MAC address:

    sudo iptables -I INPUT -m mac --mac-source <macaddress> -j RMIRROR --target <rmirrorip>

MAC address is formatted as AA:BB:CC:DD:EE:FF

IPs (source, dest, rmirror) are formatted as: 255.255.255.255

rmirrorip is the IP address of the system you want to send GRE encapsulated traffic to

## Preventing Fragmentation
Goal is to reduce packet size for all regular traffic, and allow an exception for GRE traffic

set the MTU for interfaces to 1400 with:

    sudo ifconfig eth0 mtu 1400

Add an exception for the route to the GRE destination with:

    sudo ip route to <gre target IP> dev <eth dev> mtu 1492
 - Add this rule for each interface that can reach the gre destination

