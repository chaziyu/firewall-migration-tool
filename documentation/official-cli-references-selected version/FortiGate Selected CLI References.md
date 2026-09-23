# FortiGate Selected CLI References

---

## config_firewall_address_references.md

# config firewall address references

> Source: `config firewall address references.pdf`
> Repeated FortiOS page headers and footers were omitted.
> CLI spelling and parameter terminology follow the FortiOS 7.4.6 reference.

### config firewall address

Configure IPv4 addresses.

#### Syntax

```text

config firewall address
Description: Configure IPv4 addresses.
edit <name>
set allow-routing [enable|disable]
set associated-interface {string}
set cache-ttl {integer}
set clearpass-spt [unknown|healthy|...]
set color {integer}
set comment {var-string}
set country {string}
set end-ip {ipv4-address-any}
set epg-name {string}
set fabric-object [enable|disable]
set filter {var-string}
set fqdn {string}
set fsso-group <name1>, <name2>, ...
set hw-model {string}
set hw-vendor {string}
set interface {string}
config list
Description: IP address list.
edit <ip>
next
end
set macaddr <macaddr1>, <macaddr2>, ...
set node-ip-only [enable|disable]
set obj-id {var-string}
set obj-tag {string}
set obj-type [ip|mac]
set organization {string}
set os {string}
set policy-group {string}
set route-tag {integer}
set sdn {string}
set sdn-addr-type [private|public|...]
set sdn-tag {string}
set start-ip {ipv4-address-any}
set sub-type [sdn|clearpass-spt|...]
set subnet {ipv4-classnet-any}
set subnet-name {string}
set sw-version {string}
set tag-detection-level {string}
set tag-type {string}
config tagging
Description: Config object tagging.
edit <name>
set category {string}
set tags <name1>, <name2>, ...
next
end
set tenant {string}
set type [ipmask|iprange|...]
set uuid {uuid}
set wildcard {ipv4-classnet-any}
set wildcard-fqdn {string}
next
end

```

#### Parameters

```text

config firewall address
Parameter Description Type Size Default
allow-routing Enable/disable use of this address in the static
route configuration.
option - disable
Option Description
enable Enable use of this address in the static route configuration.
disable Disable use of this address in the static route configuration.
Parameter Description Type Size Default
associated-
interface
Network interface associated with address. string Maximum
length: 35
cache-ttl Defines the minimal TTL of individual IP
addresses in FQDN cache measured in
seconds.
integer Minimum
value: 0
Maximum
value: 86400
0
clearpass-spt SPT (System Posture Token) value. option - unknown
Option Description
unknown UNKNOWN.
healthy HEALTHY.
quarantine QUARANTINE.
checkup CHECKUP.
transient TRANSIENT.
infected INFECTED.
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
comment Comment. var-string Maximum
length: 255
country IP addresses associated to a specific country. string Maximum
length: 2
end-ip Final IP address (inclusive) in the range for the
address.
ipv4-
address-
any
Not Specified 0.0.0.0
epg-name Endpoint group name. string Maximum
length: 255
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
filter Match criteria filter. var-string Maximum
length: 2047
Parameter Description Type Size Default
fqdn Fully Qualified Domain Name address. string Maximum
length: 255
fsso-group
<name>
FSSO group(s).
FSSO group name.
string Maximum
length: 511
hw-model Dynamic address matching hardware model. string Maximum
length: 35
hw-vendor Dynamic address matching hardware vendor. string Maximum
length: 35
interface Name of interface whose IP address is to be
used.
string Maximum
length: 35
macaddr
<macaddr>
Multiple MAC address ranges.
MAC address ranges <start>[-<end>]
separated by space.
string Maximum
length: 127
name Address name. string Maximum
length: 79
node-ip-only Enable/disable collection of node addresses
only in Kubernetes.
option - disable
Option Description
enable Enable collection of node addresses only in Kubernetes.
disable Disable collection of node addresses only in Kubernetes.
obj-id Object ID for NSX. var-string Maximum
length: 255
obj-tag Tag of dynamic address object. string Maximum
length: 255
obj-type Object type. option - ip
Option Description
ip IP address.
mac MAC address
organization Organization domain name (Syntax:
organization/domain).
string Maximum
length: 35
os Dynamic address matching operating system. string Maximum
length: 35
policy-group Policy group name. string Maximum
length: 15
Parameter Description Type Size Default
route-tag route-tag address. integer Minimum
value: 1
Maximum
value:
4294967295
0
sdn SDN. string Maximum
length: 35
sdn-addr-type Type of addresses to collect. option - private
Option Description
private Collect private addresses only.
public Collect public addresses only.
all Collect both public and private addresses.
sdn-tag SDN Tag. string Maximum
length: 15
start-ip First IP address (inclusive) in the range for the
address.
ipv4-
address-
any
Not Specified 0.0.0.0
sub-type Sub-type of address. option - sdn
Option Description
sdn SDN address.
clearpass-spt ClearPass SPT (System Posture Token) address.
fsso FSSO address.
ems-tag FortiClient EMS tag.
fortivoice-tag FortiVoice tag.
fortinac-tag FortiNAC tag.
fortipolicy-tag FortiPolicy tag.
swc-tag Switch Controller NAC policy tag.
device-
identification
Device address.
subnet IP address and subnet mask of address. ipv4-
classnet-
any
Not Specified 0.0.0.0 0.0.0.0
subnet-name Subnet name. string Maximum
length: 255
Parameter Description Type Size Default
sw-version Dynamic address matching software version. string Maximum
length: 35
tag-detection-
level
Tag detection level of dynamic address object. string Maximum
length: 15
tag-type Tag type of dynamic address object. string Maximum
length: 63
tenant Tenant. string Maximum
length: 35
type Type of address. option - ipmask
Option Description
ipmask Standard IPv4 address with subnet mask.
iprange Range of IPv4 addresses between two specified addresses (inclusive).
fqdn Fully Qualified Domain Name address.
geography IP addresses from a specified country.
wildcard Standard IPv4 using a wildcard subnet mask.
dynamic Dynamic address object.
interface-subnet IP and subnet of interface.
mac Range of MAC addresses.
route-tag route-tag addresses.
uuid Universally Unique Identifier (UUID;
automatically assigned but can be manually
reset).
uuid Not Specified 00000000-0000-
0000-0000-
000000000000
wildcard IP address and wildcard netmask. ipv4-
classnet-
any
Not Specified 0.0.0.0 0.0.0.0
wildcard-fqdn Fully Qualified Domain Name with wildcard
characters.
string Maximum
length: 255
config list
Parameter Description Type Size Default
ip IP. string Maximum
length: 35
config tagging
Parameter Description Type Size Default
category Tag category. string Maximum
length: 63
name Tagging entry name. string Maximum
length: 63
tags <name> Tags.
Tag name.
string Maximum
length: 79

```

### config firewall address6-template

Configure IPv6 address templates.

#### Syntax

```text

config firewall address6-template
Description: Configure IPv6 address templates.
edit <name>
set fabric-object [enable|disable]
set ip6 {ipv6-network}
config subnet-segment
Description: IPv6 subnet segments.
edit <id>
set bits {integer}
set exclusive [enable|disable]
set name {string}
config values
Description: Subnet segment values.
edit <name>
set value {string}
next
end
next
end
set subnet-segment-count {integer}
next
end

```

#### Parameters

```text

config firewall address6-template
Parameter Description Type Size Default
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
```

---

## config_firewall_addrgrp.md

# config firewall addrgrp

> Source: `config firewall addrgrp.pdf`
> Repeated FortiOS page headers and footers were omitted.
> CLI spelling and parameter terminology follow the FortiOS 7.4.6 reference.

### config firewall addrgrp

Configure IPv4 address groups.

#### Syntax

```text

config firewall addrgrp
Description: Configure IPv4 address groups.
edit <name>
set allow-routing [enable|disable]
set category [default|ztna-ems-tag|...]
set color {integer}
set comment {var-string}
set exclude [enable|disable]
set exclude-member <name1>, <name2>, ...
set fabric-object [enable|disable]
set member <name1>, <name2>, ...
config tagging
Description: Config object tagging.
edit <name>
set category {string}
set tags <name1>, <name2>, ...
next
end
set type [default|folder]
set uuid {uuid}
next
end

```

#### Parameters

```text

config firewall addrgrp
Parameter Description Type Size Default
allow-routing Enable/disable use of this group in the static route
configuration.
option - disable
Option Description
enable Enable use of this group in the static route configuration.
disable Disable use of this group in the static route configuration.
category Address group category. option - default
Option Description
default Default address group category (cannot be used as ztna-ems-tag/ztna-geo-
tag in policy).
ztna-ems-tag Members must be ztna-ems-tag group or ems-tag address, can be used as
ztna-ems-tag in policy.
ztna-geo-tag Members must be ztna-geo-tag group or geographic address, can be used as
ztna-geo-tag in policy.
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
comment Comment. var-string Maximum
length: 255
exclude Enable/disable address exclusion. option - disable
Option Description
enable Enable address exclusion.
disable Disable address exclusion.
exclude-
member
<name>
Address exclusion member.
Address name.
string Maximum
length: 79
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
member
<name>
Address objects contained within the group.
Address name.
string Maximum
length: 79
name Address group name. string Maximum
length: 79
type Address group type. option - default
Option Description
default Default address group type (address may belong to multiple groups).
folder Address folder group (members may not belong to any other group).
uuid Universally Unique Identifier (UUID; automatically
assigned but can be manually reset).
uuid Not
Specified
00000000-0000-
0000-0000-
000000000000
config tagging
Parameter Description Type Size Default
category Tag category. string Maximum
length: 63
Parameter Description Type Size Default
name Tagging entry name. string Maximum
length: 63
tags <name> Tags.
Tag name.
string Maximum
length: 79

```

### config firewall addrgrp6

Configure IPv6 address groups.

#### Syntax

```text

config firewall addrgrp6
Description: Configure IPv6 address groups.
edit <name>
set color {integer}
set comment {var-string}
set exclude [enable|disable]
set exclude-member <name1>, <name2>, ...
set fabric-object [enable|disable]
set member <name1>, <name2>, ...
config tagging
Description: Config object tagging.
edit <name>
set category {string}
set tags <name1>, <name2>, ...
next
end
set uuid {uuid}
next
end

```

#### Parameters

```text

config firewall addrgrp6
Parameter Description Type Size Default
color Integer value to determine the color of the icon in
the GUI.
integer Minimum
value: 0
Maximum
value: 32
0
comment Comment. var-string Maximum
length: 255
exclude Enable/disable address6 exclusion. option - disable
Option Description
enable Enable address6 exclusion.
disable Disable address6 exclusion.
```

---

## config_firewall_ippool.md

# config firewall ippool

> Source: `config firewal ippool.pdf`
> Repeated FortiOS page headers and footers were omitted.
> CLI spelling and parameter terminology follow the FortiOS 7.4.6 reference.

### config firewall ippool

Configure IPv4 IP pools.

#### Syntax

```text

config firewall ippool
Description: Configure IPv4 IP pools.
edit <name>
set add-nat64-route [disable|enable]
set arp-intf {string}
set arp-reply [disable|enable]
set associated-interface {string}
set block-size {integer}
set cgn-block-size {integer}
set cgn-client-endip {var-string}
set cgn-client-ipv6shift {integer}
set cgn-client-startip {var-string}
set cgn-fixedalloc [disable|enable]
set cgn-overload [disable|enable]
set cgn-port-end {integer}
set cgn-port-start {integer}
set cgn-spa [disable|enable]
set comments {var-string}
set endip {ipv4-address-any}
set endport {integer}
set exclude-ip <ip1>, <ip2>, ...
set nat64 [disable|enable]
set num-blocks-per-user {integer}
set pba-interim-log {integer}
set pba-timeout {integer}
set permit-any-host [disable|enable]
set port-per-user {integer}
set source-endip {ipv4-address-any}
set source-startip {ipv4-address-any}
set startip {ipv4-address-any}
set startport {integer}
set subnet-broadcast-in-ippool [disable|enable]
set type [overload|one-to-one|...]
set utilization-alarm-clear {integer}
set utilization-alarm-raise {integer}
next
end

```

#### Parameters

```text

config firewall ippool
Parameter Description Type Size Default
add-nat64-
route
Enable/disable adding NAT64 route. option - enable
Option Description
disable Disable adding NAT64 route.
enable Enable adding NAT64 route.
Parameter Description Type Size Default
arp-intf Select an interface from available options that will reply
to ARP requests. (If blank, any is selected).
string Maximum
length: 15
arp-reply Enable/disable replying to ARP requests when an IP
Pool is added to a policy.
option - enable
Option Description
disable Disable ARP reply.
enable Enable ARP reply.
associated-
interface
Associated interface name. string Maximum
length: 15
block-size Number of addresses in a block. integer Minimum
value: 64
Maximum
value: 4096
128
cgn-block-
size *
Number of ports in a block. integer Minimum
value: 64
Maximum
value: 4096
128
cgn-client-
endip *
Final client IPv4 address (inclusive) (format
xxx.xxx.xxx.xxx, Default: 0.0.0.0).
var-string Maximum
length: 255
cgn-client-
ipv6shift *
IPv6 shift for fixed-allocation. integer Minimum
value: 0
Maximum
value: 127
0
cgn-client-
startip *
First client IPv4 address (inclusive) (format
xxx.xxx.xxx.xxx, Default: 0.0.0.0).
var-string Maximum
length: 255
cgn-fixedalloc
*
Enable/disable fixed-allocation mode. option - disable
Option Description
disable Disable fixed-allocation mode.
enable Enable fixed-allocation mode.
cgn-overload
*
Enable/disable overload mode. option - disable
Option Description
disable Disable overload mode.
enable Enable overload mode.
Parameter Description Type Size Default
cgn-port-end * Ending public port can be allocated. integer Minimum
value: 1024
Maximum
value:
65535
65530
cgn-port-start
*
Starting public port can be allocated. integer Minimum
value: 1024
Maximum
value:
65535
5117
cgn-spa * Enable/disable single port allocation mode. option - disable
Option Description
disable Disable SPA mode.
enable Enable SPA mode.
comments Comment. var-string Maximum
length: 255
endip Final IPv4 address (inclusive) in the range for the
address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).
ipv4-
address-
any
Not
Specified
0.0.0.0
endport Final port number (inclusive) in the range for the
address pool (Default: 65533).
integer Minimum
value: 5117
Maximum
value:
65533
65533
exclude-ip
<ip> *
Exclude IPs x.x.x.x.
Exclude IPs (xxx.xxx.xxx.xxx)
string Maximum
length: 79
name IP pool name. string Maximum
length: 79
nat64 Enable/disable NAT64. option - disable
Option Description
disable Disable DNAT64.
enable Enable DNAT64.
num-blocks-
per-user
Number of addresses blocks that can be used by a user. integer Minimum
value: 1
Maximum
value: 128
8
Parameter Description Type Size Default
pba-interim-
log
Port block allocation interim logging interval. integer Minimum
value: 600
Maximum
value:
86400
0
pba-timeout Port block allocation timeout (seconds). integer Minimum
value: 3
Maximum
value:
86400
30
permit-any-
host
Enable/disable full cone NAT. option - disable
Option Description
disable Disable full cone NAT.
enable Enable full cone NAT.
port-per-user Number of port for each user. integer Minimum
value: 32
Maximum
value:
60417
0
source-endip Final IPv4 address (inclusive) in the range of the source
addresses to be translated (format xxx.xxx.xxx.xxx,
Default: 0.0.0.0).
ipv4-
address-
any
Not
Specified
0.0.0.0
source-startip First IPv4 address. ipv4-
address-
any
Not
Specified
0.0.0.0
startip First IPv4 address (inclusive) in the range for the
address pool (format xxx.xxx.xxx.xxx, Default: 0.0.0.0).
ipv4-
address-
any
Not
Specified
0.0.0.0
startport First port number (inclusive) in the range for the address
pool (Default: 5117).
integer Minimum
value: 5117
Maximum
value:
65533
5117
subnet-
broadcast-in-
ippool
Enable/disable inclusion of the subnetwork address and
broadcast IP address in the NAT64 IP pool.
option - enable
Parameter Description Type Size Default
Option Description
disable Do not include the subnetwork address and broadcast IP address in the
NAT64 IP pool.
enable Include the subnetwork address and broadcast IP address in the NAT64 IP
pool.
type IP pool type: overload, one-to-one, fixed-port-range,
port-block-allocation, cgn-resource-allocation
(hyperscale vdom only)
option - overload
Option Description
overload IP addresses in the IP pool can be shared by clients.
one-to-one One to one mapping.
fixed-port-range Fixed port range.
port-block-
allocation
Port block allocation.
utilization-
alarm-clear *
Pool utilization alarm clear threshold. integer Minimum
value: 40
Maximum
value: 100
80
utilization-
alarm-raise *
Pool utilization alarm raise threshold. integer Minimum
value: 50
Maximum
value: 100
100
- This parameter may not exist in some models.

```

### config firewall ippool6

Configure IPv6 IP pools.

#### Syntax

```text

config firewall ippool6
Description: Configure IPv6 IP pools.
edit <name>
set add-nat46-route [disable|enable]
set comments {var-string}
set endip {ipv6-address}
set nat46 [disable|enable]
set startip {ipv6-address}
next
end

```

---

## config_firewall_policy.md

# config firewall policy

> Source: `config firewall policy.pdf`
> Repeated FortiOS page headers and footers were omitted.
> CLI spelling and parameter terminology follow the FortiOS 7.4.6 reference.

> The first PDF page begins with the tail of the preceding on-demand-sniffer parameter table; that carry-over is retained below.

### config firewall on-demand-sniffer - carry-over from first PDF page

#### Parameters

```text

config firewall on-demand-sniffer
Parameter Description Type Size Default
advanced-filter Advanced freeform filter that will be used over existing
filter settings if set. Can only be used by super admin.
var-string Maximum
length: 255
hosts <host> IPv4 or IPv6 hosts to filter in this traffic sniffer.
IPv4 or IPv6 host.
string Maximum
length: 255
interface Interface name that on-demand packet sniffer will take
place.
string Maximum
length: 35
max-packet-
count
Maximum number of packets to capture per on-
demand packet sniffer.
integer Minimum
value: 1
Maximum
value:
20000 **
0
name On-demand packet sniffer name. string Maximum
length: 35
non-ip-packet Include non-IP packets. option - disable
Option Description
enable Enable non-IP packets to be included capture.
disable Disable non-IP packets to be included in capture.
ports <port> Ports to filter for in this traffic sniffer.
Port to filter in this traffic sniffer.
integer Minimum
value: 1
Maximum
value:
65536
protocols
<protocol>
Protocols to filter in this traffic sniffer.
Integer value for the protocol type as defined by IANA
(0 - 255).
integer Minimum
value: 0
Maximum
value: 255
** Values may differ between models.

```

### config firewall policy

Configure IPv4/IPv6 policies.

#### Syntax

```text

config firewall policy
Description: Configure IPv4/IPv6 policies.
edit <policyid>
set action [accept|deny|...]
set anti-replay [enable|disable]
set application-list {string}
set auth-cert {string}
set auth-path [enable|disable]
set auth-redirect-addr {string}
set auto-asic-offload [enable|disable]
set av-profile {string}
set block-notification [enable|disable]
set captive-portal-exempt [enable|disable]
set capture-packet [enable|disable]
set casb-profile {string}
set cifs-profile {string}
set comments {var-string}
set custom-log-fields <field-id1>, <field-id2>, ...
set decrypted-traffic-mirror {string}
set delay-tcp-npu-session [enable|disable]
set diameter-filter-profile {string}
set diffserv-copy [enable|disable]
set diffserv-forward [enable|disable]
set diffserv-reverse [enable|disable]
set diffservcode-forward {user}
set diffservcode-rev {user}
set disclaimer [enable|disable]
set dlp-profile {string}
set dnsfilter-profile {string}
set dsri [enable|disable]
set dstaddr <name1>, <name2>, ...
set dstaddr-negate [enable|disable]
set dstaddr6 <name1>, <name2>, ...
set dstaddr6-negate [enable|disable]
set dstintf <name1>, <name2>, ...
set dynamic-shaping [enable|disable]
set email-collect [enable|disable]
set emailfilter-profile {string}
set fec [enable|disable]
set file-filter-profile {string}
set firewall-session-dirty [check-all|check-new]
set fixedport [enable|disable]
set fsso-agent-for-ntlm {string}
set fsso-groups <name1>, <name2>, ...
set geoip-anycast [enable|disable]
set geoip-match [physical-location|registered-location]
set groups <name1>, <name2>, ...
set http-policy-redirect [enable|disable]
set icap-profile {string}
set identity-based-route {string}
set inbound [enable|disable]
set inspection-mode [proxy|flow]
set internet-service [enable|disable]
set internet-service-custom <name1>, <name2>, ...
set internet-service-custom-group <name1>, <name2>, ...
set internet-service-group <name1>, <name2>, ...
set internet-service-name <name1>, <name2>, ...
set internet-service-negate [enable|disable]
set internet-service-src [enable|disable]
set internet-service-src-custom <name1>, <name2>, ...
set internet-service-src-custom-group <name1>, <name2>, ...
set internet-service-src-group <name1>, <name2>, ...
set internet-service-src-name <name1>, <name2>, ...
set internet-service-src-negate [enable|disable]
set internet-service6 [enable|disable]
set internet-service6-custom <name1>, <name2>, ...
set internet-service6-custom-group <name1>, <name2>, ...
set internet-service6-group <name1>, <name2>, ...
set internet-service6-name <name1>, <name2>, ...
set internet-service6-negate [enable|disable]
set internet-service6-src [enable|disable]
set internet-service6-src-custom <name1>, <name2>, ...
set internet-service6-src-custom-group <name1>, <name2>, ...
set internet-service6-src-group <name1>, <name2>, ...
set internet-service6-src-name <name1>, <name2>, ...
set internet-service6-src-negate [enable|disable]
set ippool [enable|disable]
set ips-sensor {string}
set ips-voip-filter {string}
set logtraffic [all|utm|...]
set logtraffic-start [enable|disable]
set match-vip [enable|disable]
set match-vip-only [enable|disable]
set name {string}
set nat [enable|disable]
set nat46 [enable|disable]
set nat64 [enable|disable]
set natinbound [enable|disable]
set natip {ipv4-classnet}
set natoutbound [enable|disable]
set network-service-dynamic <name1>, <name2>, ...
set network-service-src-dynamic <name1>, <name2>, ...
set np-acceleration [enable|disable]
set ntlm [enable|disable]
set ntlm-enabled-browsers <user-agent-string1>, <user-agent-string2>, ...
set ntlm-guest [enable|disable]
set outbound [enable|disable]
set passive-wan-health-measurement [enable|disable]
set pcp-inbound [enable|disable]
set pcp-outbound [enable|disable]
set pcp-poolname <name1>, <name2>, ...
set per-ip-shaper {string}
set permit-any-host [enable|disable]
set permit-stun-host [enable|disable]
set policy-expiry [enable|disable]
set policy-expiry-date {datetime}
set policy-expiry-date-utc {user}
set poolname <name1>, <name2>, ...
set poolname6 <name1>, <name2>, ...
set port-preserve [enable|disable]
set profile-group {string}
set profile-protocol-options {string}
set profile-type [single|group]
set radius-mac-auth-bypass [enable|disable]
set redirect-url {var-string}
set replacemsg-override-group {string}
set reputation-direction [source|destination]
set reputation-direction6 [source|destination]
set reputation-minimum {integer}
set reputation-minimum6 {integer}
set rtp-addr <name1>, <name2>, ...
set rtp-nat [disable|enable]
set schedule {string}
set schedule-timeout [enable|disable]
set sctp-filter-profile {string}
set send-deny-packet [disable|enable]
set service <name1>, <name2>, ...
set service-negate [enable|disable]
set session-ttl {user}
set sgt <id1>, <id2>, ...
set sgt-check [enable|disable]
set src-vendor-mac <id1>, <id2>, ...
set srcaddr <name1>, <name2>, ...
set srcaddr-negate [enable|disable]
set srcaddr6 <name1>, <name2>, ...
set srcaddr6-negate [enable|disable]
set srcintf <name1>, <name2>, ...
set ssh-filter-profile {string}
set ssh-policy-redirect [enable|disable]
set ssl-ssh-profile {string}
set status [enable|disable]
set tcp-mss-receiver {integer}
set tcp-mss-sender {integer}
set tcp-session-without-syn [all|data-only|...]
set timeout-send-rst [enable|disable]
set tos {user}
set tos-mask {user}
set tos-negate [enable|disable]
set traffic-shaper {string}
set traffic-shaper-reverse {string}
set users <name1>, <name2>, ...
set utm-status [enable|disable]
set uuid {uuid}
set videofilter-profile {string}
set virtual-patch-profile {string}
set vlan-cos-fwd {integer}
set vlan-cos-rev {integer}
set vlan-filter {user}
set voip-profile {string}
set vpntunnel {string}
set waf-profile {string}
set wanopt [enable|disable]
set wanopt-detection [active|passive|...]
set wanopt-passive-opt [default|transparent|...]
set wanopt-peer {string}
set wanopt-profile {string}
set wccp [enable|disable]
set webcache [enable|disable]
set webcache-https [disable|enable]
set webfilter-profile {string}
set webproxy-forward-server {string}
set webproxy-profile {string}
set ztna-device-ownership [enable|disable]
set ztna-ems-tag <name1>, <name2>, ...
set ztna-ems-tag-secondary <name1>, <name2>, ...
set ztna-geo-tag <name1>, <name2>, ...
set ztna-policy-redirect [enable|disable]
set ztna-status [enable|disable]
set ztna-tags-match-logic [or|and]
next
end

```

#### Parameters

```text

config firewall policy
Parameter Description Type Size Default
action Policy action (accept/deny/ipsec). option - deny
Option Description
accept Allows session that match the firewall policy.
deny Blocks sessions that match the firewall policy.
ipsec Firewall policy becomes a policy-based IPsec VPN policy.
anti-replay Enable/disable anti-replay check. option - enable
Option Description
enable Enable anti-replay check.
disable Disable anti-replay check.
application-list Name of an existing Application list. string Maximum
length: 35
auth-cert HTTPS server certificate for policy
authentication.
string Maximum
length: 35
auth-path Enable/disable authentication-based routing. option - disable
Option Description
enable Enable authentication-based routing.
disable Disable authentication-based routing.
auth-redirect-
addr
HTTP-to-HTTPS redirect address for firewall
authentication.
string Maximum
length: 63
auto-asic-
offload *
Enable/disable policy traffic ASIC offloading. option - enable
Option Description
enable Enable auto ASIC offloading.
disable Disable ASIC offloading.
Parameter Description Type Size Default
av-profile Name of an existing Antivirus profile. string Maximum
length: 35
block-
notification
Enable/disable block notification. option - disable
Option Description
enable Enable setting.
disable Disable setting.
captive-portal-
exempt
Enable to exempt some users from the
captive portal.
option - disable
Option Description
enable Enable exemption of captive portal.
disable Disable exemption of captive portal.
capture-packet * Enable/disable capture packets. option - disable
Option Description
enable Enable capture packets.
disable Disable capture packets.
casb-profile Name of an existing CASB profile. string Maximum
length: 35
cifs-profile Name of an existing CIFS profile. string Maximum
length: 35
comments Comment. var-string Maximum
length: 1023
custom-log-
fields <field-
id>
Custom fields to append to log messages for
this policy.
Custom log field.
string Maximum
length: 35
decrypted-
traffic-mirror
Decrypted traffic mirror. string Maximum
length: 35
delay-tcp-npu-
session
Enable TCP NPU session delay to guarantee
packet order of 3-way handshake.
option - disable
Option Description
enable Enable TCP NPU session delay in order to guarantee packet order of 3-way
handshake.
Parameter Description Type Size Default
Option Description
disable Disable TCP NPU session delay in order to guarantee packet order of 3-way
handshake.
diameter-filter-
profile
Name of an existing Diameter filter profile. string Maximum
length: 35
diffserv-copy Enable to copy packet's DiffServ values from
session's original direction to its reply
direction.
option - disable
Option Description
enable Enable DSCP copy.
disable Disable DSCP copy.
diffserv-forward Enable to change packet's DiffServ values to
the specified diffservcode-forward value.
option - disable
Option Description
enable Enable setting forward (original) traffic Diffserv.
disable Disable setting forward (original) traffic Diffserv.
diffserv-reverse Enable to change packet's reverse (reply)
DiffServ values to the specified diffservcode-
rev value.
option - disable
Option Description
enable Enable setting reverse (reply) traffic DiffServ.
disable Disable setting reverse (reply) traffic DiffServ.
diffservcode-
forward
Change packet's DiffServ to this value. user Not Specified
diffservcode-rev Change packet's reverse (reply) DiffServ to
this value.
user Not Specified
disclaimer Enable/disable user authentication
disclaimer.
option - disable
Option Description
enable Enable user authentication disclaimer.
disable Disable user authentication disclaimer.
Parameter Description Type Size Default
dlp-profile Name of an existing DLP profile. string Maximum
length: 35
dnsfilter-profile Name of an existing DNS filter profile. string Maximum
length: 35
dsri Enable DSRI to ignore HTTP server
responses.
option - disable
Option Description
enable Enable DSRI.
disable Disable DSRI.
dstaddr <name> Destination IPv4 address and address group
names.
Address name.
string Maximum
length: 79
dstaddr-negate When enabled dstaddr specifies what the
destination address must NOT be.
option - disable
Option Description
enable Enable destination address negate.
disable Disable destination address negate.
dstaddr6
<name>
Destination IPv6 address name and address
group names.
Address name.
string Maximum
length: 79
dstaddr6-
negate
When enabled dstaddr6 specifies what the
destination address must NOT be.
option - disable
Option Description
enable Enable IPv6 destination address negate.
disable Disable IPv6 destination address negate.
dstintf <name> Outgoing (egress) interface.
Interface name.
string Maximum
length: 79
dynamic-
shaping
Enable/disable dynamic RADIUS defined
traffic shaping.
option - disable
Option Description
enable Enable dynamic RADIUS defined traffic shaping.
disable Disable dynamic RADIUS defined traffic shaping.
Parameter Description Type Size Default
email-collect Enable/disable email collection. option - disable
Option Description
enable Enable email collection.
disable Disable email collection.
emailfilter-
profile
Name of an existing email filter profile. string Maximum
length: 35
fec Enable/disable Forward Error Correction on
traffic matching this policy on a FEC device.
option - disable
Option Description
enable Enable Forward Error Correction.
disable Disable Forward Error Correction.
file-filter-profile Name of an existing file-filter profile. string Maximum
length: 35
firewall-session-
dirty
How to handle sessions if the configuration of
this firewall policy changes.
option - check-all
Option Description
check-all Flush all current sessions accepted by this policy. These sessions must be
started and re-matched with policies.
check-new Continue to allow sessions already accepted by this policy.
fixedport Enable to prevent source NAT from changing
a session's source port.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
fsso-agent-for-
ntlm
FSSO agent to use for NTLM authentication. string Maximum
length: 35
fsso-groups
<name>
Names of FSSO groups.
Names of FSSO groups.
string Maximum
length: 511
geoip-anycast Enable/disable recognition of anycast IP
addresses using the geography IP database.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable recognition of anycast IP addresses using the geography IP
database.
disable Disable recognition of anycast IP addresses using the geography IP
database.
geoip-match Match geography address based either on its
physical location or registered location.
option - physical-location
Option Description
physical-location Match geography address to its physical location using the geography IP
database.
registered-
location
Match geography address to its registered location using the geography IP
database.
groups <name> Names of user groups that can authenticate
with this policy.
Group name.
string Maximum
length: 79
http-policy-
redirect
Redirect HTTP(S) traffic to matching
transparent web proxy policy.
option - disable
Option Description
enable Enable HTTP(S) policy redirect.
disable Disable HTTP(S) policy redirect.
icap-profile Name of an existing ICAP profile. string Maximum
length: 35
identity-based-
route
Name of identity-based routing rule. string Maximum
length: 35
inbound Policy-based IPsec VPN: only traffic from the
remote network can initiate a VPN.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
inspection-
mode
Policy inspection mode (Flow/proxy). Default
is Flow mode.
option - flow
Parameter Description Type Size Default
Option Description
proxy Proxy based inspection.
flow Flow based inspection.
internet-service Enable/disable use of Internet Services for
this policy. If enabled, destination address
and service are not used.
option - disable
Option Description
enable Enable use of Internet Services in policy.
disable Disable use of Internet Services in policy.
internet-service-
custom <name>
Custom Internet Service name.
Custom Internet Service name.
string Maximum
length: 79
internet-service-
custom-group
<name>
Custom Internet Service group name.
Custom Internet Service group name.
string Maximum
length: 79
internet-service-
group <name>
Internet Service group name.
Internet Service group name.
string Maximum
length: 79
internet-service-
name <name>
Internet Service name.
Internet Service name.
string Maximum
length: 79
internet-service-
negate
When enabled internet-service specifies
what the service must NOT be.
option - disable
Option Description
enable Enable negated Internet Service match.
disable Disable negated Internet Service match.
internet-service-
src
Enable/disable use of Internet Services in
source for this policy. If enabled, source
address is not used.
option - disable
Option Description
enable Enable use of Internet Services source in policy.
disable Disable use of Internet Services source in policy.
internet-service-
src-custom
<name>
Custom Internet Service source name.
Custom Internet Service name.
string Maximum
length: 79
Parameter Description Type Size Default
internet-service-
src-custom-
group <name>
Custom Internet Service source group name.
Custom Internet Service group name.
string Maximum
length: 79
internet-service-
src-group
<name>
Internet Service source group name.
Internet Service group name.
string Maximum
length: 79
internet-service-
src-name
<name>
Internet Service source name.
Internet Service name.
string Maximum
length: 79
internet-service-
src-negate
When enabled internet-service-src specifies
what the service must NOT be.
option - disable
Option Description
enable Enable negated Internet Service source match.
disable Disable negated Internet Service source match.
internet-
service6
Enable/disable use of IPv6 Internet Services
for this policy. If enabled, destination address
and service are not used.
option - disable
Option Description
enable Enable use of IPv6 Internet Services in policy.
disable Disable use of IPv6 Internet Services in policy.
internet-
service6-
custom <name>
Custom IPv6 Internet Service name.
Custom Internet Service name.
string Maximum
length: 79
internet-
service6-
custom-group
<name>
Custom Internet Service6 group name.
Custom Internet Service6 group name.
string Maximum
length: 79
internet-
service6-group
<name>
Internet Service group name.
Internet Service group name.
string Maximum
length: 79
internet-
service6-name
<name>
IPv6 Internet Service name.
IPv6 Internet Service name.
string Maximum
length: 79
internet-
service6-negate
When enabled internet-service6 specifies
what the service must NOT be.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable negated IPv6 Internet Service match.
disable Disable negated IPv6 Internet Service match.
internet-
service6-src
Enable/disable use of IPv6 Internet Services
in source for this policy. If enabled, source
address is not used.
option - disable
Option Description
enable Enable use of IPv6 Internet Services source in policy.
disable Disable use of IPv6 Internet Services source in policy.
internet-
service6-src-
custom <name>
Custom IPv6 Internet Service source name.
Custom Internet Service name.
string Maximum
length: 79
internet-
service6-src-
custom-group
<name>
Custom Internet Service6 source group
name.
Custom Internet Service6 group name.
string Maximum
length: 79
internet-
service6-src-
group <name>
Internet Service6 source group name.
Internet Service group name.
string Maximum
length: 79
internet-
service6-src-
name <name>
IPv6 Internet Service source name.
Internet Service name.
string Maximum
length: 79
internet-
service6-src-
negate
When enabled internet-service6-src specifies
what the service must NOT be.
option - disable
Option Description
enable Enable negated IPv6 Internet Service source match.
disable Disable negated IPv6 Internet Service source match.
ippool Enable to use IP Pools for source NAT. option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
ips-sensor Name of an existing IPS sensor. string Maximum
length: 35
ips-voip-filter Name of an existing VoIP (ips) profile. string Maximum
length: 35
logtraffic Enable or disable logging. Log all sessions or
security profile sessions.
option - utm
Option Description
all Log all sessions accepted or denied by this policy.
utm Log traffic that has a security profile applied to it.
disable Disable all logging for this policy.
logtraffic-start Record logs when a session starts. option - disable
Option Description
enable Enable setting.
disable Disable setting.
match-vip Enable to match packets that have had their
destination addresses changed by a VIP.
option - enable
Option Description
enable Match DNATed packet.
disable Do not match DNATed packet.
match-vip-only Enable/disable matching of only those
packets that have had their destination
addresses changed by a VIP.
option - disable
Option Description
enable Enable matching of only those packets that have had their destination
addresses changed by a VIP.
disable Disable matching of only those packets that have had their destination
addresses changed by a VIP.
name Policy name. string Maximum
length: 35
nat Enable/disable source NAT. option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
nat46 Enable/disable NAT46. option - disable
Option Description
enable Enable NAT46.
disable Disable NAT46.
nat64 Enable/disable NAT64. option - disable
Option Description
enable Enable NAT64.
disable Disable NAT64.
natinbound Policy-based IPsec VPN: apply destination
NAT to inbound traffic.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
natip Policy-based IPsec VPN: source NAT IP
address for outgoing traffic.
ipv4-
classnet
Not Specified 0.0.0.0 0.0.0.0
natoutbound Policy-based IPsec VPN: apply source NAT
to outbound traffic.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
network-
service-dynamic
<name>
Dynamic Network Service name.
Dynamic Network Service name.
string Maximum
length: 79
network-
service-src-
dynamic
<name>
Dynamic Network Service source name.
Dynamic Network Service name.
string Maximum
length: 79
Parameter Description Type Size Default
np-acceleration
*
Enable/disable UTM Network Processor
acceleration.
option - enable
Option Description
enable Enable UTM Network Processor acceleration.
disable Disable UTM Network Processor acceleration.
ntlm Enable/disable NTLM authentication. option - disable
Option Description
enable Enable setting.
disable Disable setting.
ntlm-enabled-
browsers
<user-agent-
string>
HTTP-User-Agent value of supported
browsers.
User agent string.
string Maximum
length: 79
ntlm-guest Enable/disable NTLM guest user access. option - disable
Option Description
enable Enable setting.
disable Disable setting.
outbound Policy-based IPsec VPN: only traffic from the
internal network can initiate a VPN.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
passive-wan-
health-
measurement
Enable/disable passive WAN health
measurement. When enabled, auto-asic-
offload is disabled.
option - disable
Option Description
enable Enable Passive WAN health measurement.
disable Disable Passive WAN health measurement.
pcp-inbound Enable/disable PCP inbound DNAT. option - disable
Parameter Description Type Size Default
Option Description
enable Enable PCP inbound DNAT.
disable Disable PCP inbound DNAT.
pcp-outbound Enable/disable PCP outbound SNAT. option - disable
Option Description
enable Enable PCP outbound SNAT.
disable Disable PCP outbound SNAT.
pcp-poolname
<name>
PCP pool names.
PCP pool name.
string Maximum
length: 79
per-ip-shaper Per-IP traffic shaper. string Maximum
length: 35
permit-any-host Accept UDP packets from any host. option - disable
Option Description
enable Enable setting.
disable Disable setting.
permit-stun-host Accept UDP packets from any Session
Traversal Utilities for NAT (STUN) host.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
policy-expiry Enable/disable policy expiry. option - disable
Option Description
enable Enable policy expiry.
disable Disable polcy expiry.
policy-expiry-
date
Policy expiry date (YYYY-MM-DD
HH:MM:SS).
datetime Not Specified 0000-00-00
00:00:00
policy-expiry-
date-utc
Policy expiry date and time, in epoch format. user Not Specified
Parameter Description Type Size Default
policyid Policy ID. integer Minimum
value: 0
Maximum
value:
4294967294
0
poolname
<name>
IP Pool names.
IP pool name.
string Maximum
length: 79
poolname6
<name>
IPv6 pool names.
IPv6 pool name.
string Maximum
length: 79
port-preserve Enable/disable preservation of the original
source port from source NAT if it has not
been used.
option - enable
Option Description
enable Use the original source port if it has not been used.
disable Source NAT always changes the source port.
profile-group Name of profile group. string Maximum
length: 35
profile-protocol-
options
Name of an existing Protocol options profile. string Maximum
length: 35
default
profile-type Determine whether the firewall policy allows
security profile groups or single profiles only.
option - single
Option Description
single Do not allow security profile groups.
group Allow security profile groups.
radius-mac-
auth-bypass
Enable MAC authentication bypass. The
bypassed MAC address must be received
from RADIUS server.
option - disable
Option Description
enable Enable MAC authentication bypass.
disable Disable MAC authentication bypass.
redirect-url URL users are directed to after seeing and
accepting the disclaimer or authenticating.
var-string Maximum
length: 1023
replacemsg-
override-group
Override the default replacement message
group for this policy.
string Maximum
length: 35
Parameter Description Type Size Default
reputation-
direction
Direction of the initial traffic for reputation to
take effect.
option - destination
Option Description
source Check reputation for source address.
destination Check reputation for destination address.
reputation-
direction6
Direction of the initial traffic for IPv6
reputation to take effect.
option - destination
Option Description
source Check reputation for IPv6 source address.
destination Check reputation for IPv6 destination address.
reputation-
minimum
Minimum Reputation to take action. integer Minimum
value: 0
Maximum
value:
4294967295
0
reputation-
minimum6
IPv6 Minimum Reputation to take action. integer Minimum
value: 0
Maximum
value:
4294967295
0
rtp-addr
<name>
Address names if this is an RTP NAT policy.
Address name.
string Maximum
length: 79
rtp-nat Enable Real Time Protocol (RTP) NAT. option - disable
Option Description
disable Disable setting.
enable Enable setting.
schedule Schedule name. string Maximum
length: 35
schedule-
timeout
Enable to force current sessions to end when
the schedule object times out. Disable allows
them to end from inactivity.
option - disable
Option Description
enable Enable schedule timeout.
disable Disable schedule timeout.
Parameter Description Type Size Default
sctp-filter-profile Name of an existing SCTP filter profile. string Maximum
length: 35
send-deny-
packet
Enable to send a reply when a session is
denied or blocked by a firewall policy.
option - disable
Option Description
disable Disable deny-packet sending.
enable Enable deny-packet sending.
service <name> Service and service group names.
Service and service group names.
string Maximum
length: 79
service-negate When enabled service specifies what the
service must NOT be.
option - disable
Option Description
enable Enable negated service match.
disable Disable negated service match.
session-ttl TTL in seconds for sessions accepted by this
policy.
user Not Specified
sgt <id> Security group tags.
Security group tag (1 - 65535).
integer Minimum
value: 1
Maximum
value: 65535
sgt-check Enable/disable security group tags (SGT)
check.
option - disable
Option Description
enable Enable SGT check.
disable Disable SGT check.
src-vendor-mac
<id>
Vendor MAC source ID.
Vendor MAC ID.
integer Minimum
value: 0
Maximum
value:
4294967295
srcaddr <name> Source IPv4 address and address group
names.
Address name.
string Maximum
length: 79
Parameter Description Type Size Default
srcaddr-negate When enabled srcaddr specifies what the
source address must NOT be.
option - disable
Option Description
enable Enable source address negate.
disable Disable source address negate.
srcaddr6
<name>
Source IPv6 address name and address
group names.
Address name.
string Maximum
length: 79
srcaddr6-
negate
When enabled srcaddr6 specifies what the
source address must NOT be.
option - disable
Option Description
enable Enable IPv6 source address negate.
disable Disable IPv6 source address negate.
srcintf <name> Incoming (ingress) interface.
Interface name.
string Maximum
length: 79
ssh-filter-profile Name of an existing SSH filter profile. string Maximum
length: 35
ssh-policy-
redirect
Redirect SSH traffic to matching transparent
proxy policy.
option - disable
Option Description
enable Enable SSH policy redirect.
disable Disable SSH policy redirect.
ssl-ssh-profile Name of an existing SSL SSH profile. string Maximum
length: 35
no-inspection
status Enable or disable this policy. option - enable
Option Description
enable Enable setting.
disable Disable setting.
tcp-mss-
receiver
Receiver TCP maximum segment size
(MSS).
integer Minimum
value: 0
Maximum
value: 65535
0
Parameter Description Type Size Default
tcp-mss-sender Sender TCP maximum segment size (MSS). integer Minimum
value: 0
Maximum
value: 65535
0
tcp-session-
without-syn
Enable/disable creation of TCP session
without SYN flag.
option - disable
Option Description
all Enable TCP session without SYN.
data-only Enable TCP session data only.
disable Disable TCP session without SYN.
timeout-send-rst Enable/disable sending RST packets when
TCP sessions expire.
option - disable
Option Description
enable Enable sending of RST packet upon TCP session expiration.
disable Disable sending of RST packet upon TCP session expiration.
tos ToS (Type of Service) value used for
comparison.
user Not Specified
tos-mask Non-zero bit positions are used for
comparison while zero bit positions are
ignored.
user Not Specified
tos-negate Enable negated TOS match. option - disable
Option Description
enable Enable TOS match negate.
disable Disable TOS match negate.
traffic-shaper Traffic shaper. string Maximum
length: 35
traffic-shaper-
reverse
Reverse traffic shaper. string Maximum
length: 35
users <name> Names of individual users that can
authenticate with this policy.
Names of individual users that can
authenticate with this policy.
string Maximum
length: 79
utm-status Enable to add one or more security profiles
(AV, IPS, etc.) to the firewall policy.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
uuid Universally Unique Identifier (UUID;
automatically assigned but can be manually
reset).
uuid Not Specified 00000000-0000-
0000-0000-
000000000000
videofilter-
profile
Name of an existing VideoFilter profile. string Maximum
length: 35
virtual-patch-
profile
Name of an existing virtual-patch profile. string Maximum
length: 35
vlan-cos-fwd VLAN forward direction user priority: 255
passthrough, 0 lowest, 7 highest.
integer Minimum
value: 0
Maximum
value: 7
255
vlan-cos-rev VLAN reverse direction user priority: 255
passthrough, 0 lowest, 7 highest.
integer Minimum
value: 0
Maximum
value: 7
255
vlan-filter VLAN ranges to allow user Not Specified
voip-profile Name of an existing VoIP (voipd) profile. string Maximum
length: 35
vpntunnel Policy-based IPsec VPN: name of the IPsec
VPN Phase 1.
string Maximum
length: 35
waf-profile Name of an existing Web application firewall
profile.
string Maximum
length: 35
wanopt * Enable/disable WAN optimization. option - disable
Option Description
enable Enable setting.
disable Disable setting.
wanopt-
detection *
WAN optimization auto-detection mode. option - active
Option Description
active Active WAN optimization peer auto-detection.
Parameter Description Type Size Default
Option Description
passive Passive WAN optimization peer auto-detection.
off Turn off WAN optimization peer auto-detection.
wanopt-
passive-opt *
WAN optimization passive mode options.
This option decides what IP address will be
used to connect server.
option - default
Option Description
default Allow client side WAN opt peer to decide.
transparent Use address of client to connect to server.
non-transparent Use local FortiGate address to connect to server.
wanopt-peer * WAN optimization peer. string Maximum
length: 35
wanopt-profile * WAN optimization profile. string Maximum
length: 35
wccp Enable/disable forwarding traffic matching
this policy to a configured WCCP server.
option - disable
Option Description
enable Enable WCCP setting.
disable Disable WCCP setting.
webcache * Enable/disable web cache. option - disable
Option Description
enable Enable setting.
disable Disable setting.
webcache-https
*
Enable/disable web cache for HTTPS. option - disable
Option Description
disable Disable web cache for HTTPS.
enable Enable web cache for HTTPS.
webfilter-profile Name of an existing Web filter profile. string Maximum
length: 35
Parameter Description Type Size Default
webproxy-
forward-server
Webproxy forward server name. string Maximum
length: 63
webproxy-
profile
Webproxy profile name. string Maximum
length: 63
ztna-device-
ownership
Enable/disable zero trust device ownership. option - disable
Option Description
enable Enable ZTNA device ownership check.
disable Disable ZTNA device ownership check.
ztna-ems-tag
<name>
Source ztna-ems-tag names.
Address name.
string Maximum
length: 79
ztna-ems-tag-
secondary
<name>
Source ztna-ems-tag-secondary names.
Address name.
string Maximum
length: 79
ztna-geo-tag
<name>
Source ztna-geo-tag names.
Address name.
string Maximum
length: 79
ztna-policy-
redirect
Redirect ZTNA traffic to matching Access-
Proxy proxy-policy.
option - disable
Option Description
enable Enable ZTNA proxy-policy redirect.
disable Disable ZTNA proxy-policy redirect.
ztna-status Enable/disable zero trust access. option - disable
Option Description
enable Enable zero trust network access.
disable Disable zero trust network access.
ztna-tags-
match-logic
ZTNA tag matching logic. option - or
Option Description
or Match ZTNA tags using a logical OR operator.
and Match ZTNA tags using a logical AND operator.
- This parameter may not exist in some models.

```

---

## config_firewall_profile_group.md

# config firewall profile-group

> Source: `config firewall profile group.pdf`
> Repeated FortiOS page headers and footers were omitted.
> CLI spelling and parameter terminology follow the FortiOS 7.4.6 reference.

### config firewall profile-group

Configure profile groups.

#### Syntax

```text

config firewall profile-group
Description: Configure profile groups.
edit <name>
set application-list {string}
set av-profile {string}
set casb-profile {string}
set cifs-profile {string}
set diameter-filter-profile {string}
set dlp-profile {string}
set dnsfilter-profile {string}
set emailfilter-profile {string}
set file-filter-profile {string}
set icap-profile {string}
set ips-sensor {string}
set ips-voip-filter {string}
set profile-protocol-options {string}
set sctp-filter-profile {string}
set ssh-filter-profile {string}
set ssl-ssh-profile {string}
set videofilter-profile {string}
set virtual-patch-profile {string}
set voip-profile {string}
set waf-profile {string}
set webfilter-profile {string}
next
end

```

#### Parameters

```text

config firewall profile-group
Parameter Description Type Size Default
application-
list
Name of an existing Application list. string Maximum
length: 35
av-profile Name of an existing Antivirus profile. string Maximum
length: 35
casb-profile Name of an existing CASB profile. string Maximum
length: 35
cifs-profile Name of an existing CIFS profile. string Maximum
length: 35
diameter-
filter-profile
Name of an existing Diameter filter profile. string Maximum
length: 35
dlp-profile Name of an existing DLP profile. string Maximum
length: 35
Parameter Description Type Size Default
dnsfilter-
profile
Name of an existing DNS filter profile. string Maximum
length: 35
emailfilter-
profile
Name of an existing email filter profile. string Maximum
length: 35
file-filter-
profile
Name of an existing file-filter profile. string Maximum
length: 35
icap-profile Name of an existing ICAP profile. string Maximum
length: 35
ips-sensor Name of an existing IPS sensor. string Maximum
length: 35
ips-voip-filter Name of an existing VoIP (ips) profile. string Maximum
length: 35
name Profile group name. string Maximum
length: 35
profile-
protocol-
options
Name of an existing Protocol options profile. string Maximum
length: 35
default
sctp-filter-
profile
Name of an existing SCTP filter profile. string Maximum
length: 35
ssh-filter-
profile
Name of an existing SSH filter profile. string Maximum
length: 35
ssl-ssh-profile Name of an existing SSL SSH profile. string Maximum
length: 35
certificate-
inspection
videofilter-
profile
Name of an existing VideoFilter profile. string Maximum
length: 35
virtual-patch-
profile
Name of an existing virtual-patch profile. string Maximum
length: 35
voip-profile Name of an existing VoIP (voipd) profile. string Maximum
length: 35
waf-profile Name of an existing Web application firewall profile. string Maximum
length: 35
webfilter-
profile
Name of an existing Web filter profile. string Maximum
length: 35

```

### config firewall profile-protocol-options

Configure protocol options.

---

## config_firewall_schedule.md

# config firewall schedule

> Source: `config firewall schedule.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
ztna-ems-tag
<name>
ZTNA EMS Tag names.
EMS Tag name.
string Maximum
length: 79
ztna-tags-
match-logic
ZTNA tag matching logic. option - or
Option Description
or Match ZTNA tags using a logical OR operator.
and Match ZTNA tags using a logical AND operator.
- This parameter may not exist in some models.

### config firewall region

Define region table. Read-only.

#### Syntax

config firewall region
Description: Define region table. Read-only.
edit <id>
set city <id1>, <id2>, ...
set name {string}
next
end

#### Parameters

config firewall region
Parameter Description Type Size Default
city <id> City ID list.
City ID.
integer Minimum
value: 0
Maximum
value:
65535
id Region ID. integer Minimum
value: 0
Maximum
value:
65535
0
name Region name. string Maximum
length: 63

### config firewall schedule group

Schedule group configuration.

#### Syntax

config firewall schedule group
Description: Schedule group configuration.
edit <name>
set color {integer}
set fabric-object [enable|disable]
set member <name1>, <name2>, ...
next
end

#### Parameters

config firewall schedule group
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
member
<name>
Schedules added to the schedule group.
Schedule name.
string Maximum
length: 79
name Schedule group name. string Maximum
length: 31

### config firewall schedule onetime

Onetime schedule configuration.

#### Syntax

config firewall schedule onetime
Description: Onetime schedule configuration.
edit <name>
set color {integer}
set end {user}
set end-utc {user}
set expiration-days {integer}
set fabric-object [enable|disable]
set start {user}
set start-utc {user}
next
end

#### Parameters

config firewall schedule onetime
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
end Schedule end date and time, format hh:mm
yyyy/mm/dd.
user Not
Specified
end-utc Schedule end date and time, in epoch format. user Not
Specified
expiration-
days
Write an event log message this many days before the
schedule expires.
integer Minimum
value: 0
Maximum
value: 100
3
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
name Onetime schedule name. string Maximum
length: 31
start Schedule start date and time, format hh:mm
yyyy/mm/dd.
user Not
Specified
start-utc Schedule start date and time, in epoch format. user Not
Specified

### config firewall schedule recurring

Recurring schedule configuration.

#### Syntax

config firewall schedule recurring
Description: Recurring schedule configuration.
edit <name>
set color {integer}
set day {option1}, {option2}, ...
set end {user}
set fabric-object [enable|disable]
set start {user}
next
end

#### Parameters

config firewall schedule recurring
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
day One or more days of the week on which the schedule is
valid. Separate the names of the days with a space.
option - none
Option Description
sunday Sunday.
monday Monday.
tuesday Tuesday.
wednesday Wednesday.
thursday Thursday.
friday Friday.
saturday Saturday.
none None.
end Time of day to end the schedule, format hh:mm. user Not
Specified
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
name Recurring schedule name. string Maximum
length: 31
start Time of day to start the schedule, format hh:mm. user Not
Specified

### config firewall security-policy

Configure NGFW IPv4/IPv6 application policies.

#### Syntax

config firewall security-policy
Description: Configure NGFW IPv4/IPv6 application policies.
edit <policyid>
set action [accept|deny]
set app-category <id1>, <id2>, ...

---

## config_firewall_service_category_service_custom_service_group.md

# config firewall service category service custom service group

> Source: `config firewall service category, service category, service group.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
status Enable or disable this policy. option - enable
Option Description
enable Enable setting.
disable Disable setting.
url-category URL categories or groups. user Not Specified
users <name> Names of individual users that can authenticate
with this policy.
User name.
string Maximum
length: 79
uuid Universally Unique Identifier (UUID;
automatically assigned but can be manually
reset).
uuid Not Specified 00000000-0000-
0000-0000-
000000000000
videofilter-
profile
Name of an existing VideoFilter profile. string Maximum
length: 35
virtual-patch-
profile
Name of an existing virtual-patch profile. string Maximum
length: 35
voip-profile Name of an existing VoIP (voipd) profile. string Maximum
length: 35
webfilter-
profile
Name of an existing Web filter profile. string Maximum
length: 35

### config firewall service category

Configure service categories.

#### Syntax

config firewall service category
Description: Configure service categories.
edit <name>
set comment {var-string}
set fabric-object [enable|disable]
next
end

#### Parameters

config firewall service category
Parameter Description Type Size Default
comment Comment. var-string Maximum
length: 255
fabric-object Security Fabric global object setting. option - disable
Parameter Description Type Size Default
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
name Service category name. string Maximum
length: 63

### config firewall service custom

Configure custom services.

#### Syntax

config firewall service custom
Description: Configure custom services.
edit <name>
set app-category <id1>, <id2>, ...
set app-service-type [disable|app-id|...]
set application <id1>, <id2>, ...
set category {string}
set check-reset-range [disable|strict|...]
set color {integer}
set comment {var-string}
set fabric-object [enable|disable]
set fqdn {string}
set helper [auto|disable|...]
set icmpcode {integer}
set icmptype {integer}
set iprange {user}
set protocol [TCP/UDP/SCTP|ICMP|...]
set protocol-number {integer}
set proxy [enable|disable]
set sctp-portrange {user}
set session-ttl {user}
set tcp-halfclose-timer {integer}
set tcp-halfopen-timer {integer}
set tcp-portrange {user}
set tcp-rst-timer {integer}
set tcp-timewait-timer {integer}
set udp-idle-timer {integer}
set udp-portrange {user}
set uuid {uuid}
next
end

#### Parameters

config firewall service custom
Parameter Description Type Size Default
app-category
<id>
Application category ID.
Application category id.
integer Minimum
value: 0
Maximum
value:
4294967295
app-service-
type
Application service type. option - disable
Option Description
disable Disable application type.
app-id Application ID.
app-category Applicatin category.
application
<id>
Application ID.
Application id.
integer Minimum
value: 0
Maximum
value:
4294967295
category Service category. string Maximum
length: 63
check-reset-
range
Configure the type of ICMP error message
verification.
option - default
Option Description
disable Disable RST range check.
strict Check RST range strictly.
default Using system default setting.
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
comment Comment. var-string Maximum
length: 255
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
Parameter Description Type Size Default
fqdn Fully qualified domain name. string Maximum
length: 255
helper Helper name. option - auto
Option Description
auto Automatically select helper based on protocol and port.
disable Disable helper.
ftp FTP.
tftp TFTP.
ras RAS.
h323 H323.
tns TNS.
mms MMS.
sip SIP.
pptp PPTP.
rtsp RTSP.
dns-udp DNS UDP.
dns-tcp DNS TCP.
pmap PMAP.
rsh RSH.
dcerpc DCERPC.
mgcp MGCP.
icmpcode ICMP code. integer Minimum
value: 0
Maximum
value: 255
icmptype ICMP type. integer Minimum
value: 0
Maximum
value:
4294967295
iprange Start and end of the IP range associated with
service.
user Not Specified
Parameter Description Type Size Default
name Custom service name. string Maximum
length: 79
protocol Protocol type based on IANA numbers. option - TCP/UDP/SCTP
Option Description
TCP/UDP/SCTP TCP, UDP and SCTP.
ICMP ICMP.
ICMP6 ICMP6.
IP IP.
HTTP HTTP - for web proxy.
FTP FTP - for web proxy.
CONNECT Connect - for web proxy.
SOCKS-TCP Socks TCP - for web proxy.
SOCKS-UDP Socks UDP - for web proxy.
ALL All - for web proxy.
protocol-
number
IP protocol number. integer Minimum
value: 0
Maximum
value: 254
0
proxy Enable/disable web proxy service. option - disable
Option Description
enable Enable setting.
disable Disable setting.
sctp-
portrange
Multiple SCTP port ranges. user Not Specified
session-ttl Session TTL. user Not Specified
tcp-halfclose-
timer
Wait time to close a TCP session waiting for an
unanswered FIN packet.
integer Minimum
value: 0
Maximum
value: 86400
0
tcp-halfopen-
timer
Wait time to close a TCP session waiting for an
unanswered open session packet.
integer Minimum
value: 0
Maximum
value: 86400
0
Parameter Description Type Size Default
tcp-portrange Multiple TCP port ranges. user Not Specified
tcp-rst-timer Set the length of the TCP CLOSE state in
seconds.
integer Minimum
value: 5
Maximum
value: 300
0
tcp-timewait-
timer
Set the length of the TCP TIME-WAIT state in
seconds.
integer Minimum
value: 0
Maximum
value: 300
0
udp-idle-timer Number of seconds before an idle UDP
connection times out.
integer Minimum
value: 0
Maximum
value: 86400
0
udp-portrange Multiple UDP port ranges. user Not Specified
uuid Universally Unique Identifier (UUID;
automatically assigned but can be manually
reset).
uuid Not Specified 00000000-0000-
0000-0000-
000000000000

### config firewall service group

Configure service groups.

#### Syntax

config firewall service group
Description: Configure service groups.
edit <name>
set color {integer}
set comment {var-string}
set fabric-object [enable|disable]
set member <name1>, <name2>, ...
set proxy [enable|disable]
set uuid {uuid}
next
end

#### Parameters

config firewall service group
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
Parameter Description Type Size Default
comment Comment. var-string Maximum
length: 255
fabric-object Security Fabric global object setting. option - disable
Option Description
enable Object is set as a security fabric-wide global object.
disable Object is local to this security fabric member.
member
<name>
Service objects contained within the group.
Service or service group name.
string Maximum
length: 79
name Service group name. string Maximum
length: 79
proxy Enable/disable web proxy service group. option - disable
Option Description
enable Enable setting.
disable Disable setting.
uuid Universally Unique Identifier (UUID; automatically
assigned but can be manually reset).
uuid Not
Specified
00000000-0000-
0000-0000-
000000000000

### config firewall shaper per-ip-shaper

---

## config_firewall_vip.md

# config firewall vip

> Source: `config firewall vip.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
Option Description
enable Enable this TTL policy.
disable Disable this TTL policy.
ttl Value/range to match against the packet's Time to
Live value.
user Not Specified

### config firewall vendor-mac

Show vendor and the MAC address they have. Read-only.

#### Syntax

config firewall vendor-mac
Description: Show vendor and the MAC address they have. Read-only.
edit <id>
set mac-number {integer}
set name {string}
set obsolete {integer}
next
end

#### Parameters

config firewall vendor-mac
Parameter Description Type Size Default
id Vendor ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
mac-number Total number of MAC addresses. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
name Vendor name. Read-only. string Maximum
length: 63
obsolete Indicates whether the Vendor ID can be used. Read-
only.
integer Minimum
value: 0
Maximum
value: 255
0

### config firewall vip

Configure virtual IP for IPv4.

#### Syntax

config firewall vip
Description: Configure virtual IP for IPv4.
edit <name>
set add-nat46-route [disable|enable]
set arp-reply [disable|enable]
set color {integer}
set comment {var-string}
set dns-mapping-ttl {integer}
set extaddr <name1>, <name2>, ...
set extintf {string}
set extip {user}
set extport {user}
set gratuitous-arp-interval {integer}
set gslb-domain-name {string}
set gslb-hostname {string}
config gslb-public-ips
Description: Publicly accessible IP addresses for the FortiGSLB service.
edit <index>
set ip {ipv4-address-any}
next
end
set h2-support [enable|disable]
set h3-support [enable|disable]
set http-cookie-age {integer}
set http-cookie-domain {string}
set http-cookie-domain-from-host [disable|enable]
set http-cookie-generation {integer}
set http-cookie-path {string}
set http-cookie-share [disable|same-ip]
set http-ip-header [enable|disable]
set http-ip-header-name {string}
set http-multiplex [enable|disable]
set http-multiplex-max-concurrent-request {integer}
set http-multiplex-max-request {integer}
set http-multiplex-ttl {integer}
set http-redirect [enable|disable]
set https-cookie-secure [disable|enable]
set id {integer}
set ipv6-mappedip {user}
set ipv6-mappedport {user}
set ldb-method [static|round-robin|...]
set mapped-addr {string}
set mappedip <range1>, <range2>, ...
set mappedport {user}
set max-embryonic-connections {integer}
set monitor <name1>, <name2>, ...
set nat-source-vip [disable|enable]
set nat44 [disable|enable]
set nat46 [disable|enable]
set one-click-gslb-server [disable|enable]
set outlook-web-access [disable|enable]
set persistence [none|http-cookie|...]
set portforward [disable|enable]
set portmapping-type [1-to-1|m-to-n]
set protocol [tcp|udp|...]
config quic
Description: QUIC setting.
set ack-delay-exponent {integer}
set active-connection-id-limit {integer}
set active-migration [enable|disable]
set grease-quic-bit [enable|disable]
set max-ack-delay {integer}
set max-datagram-frame-size {integer}
set max-idle-timeout {integer}
set max-udp-payload-size {integer}
end
config realservers
Description: Select the real servers that this server load balancing VIP will
distribute traffic to.
edit <id>
set address {string}
set client-ip {user}
set healthcheck [disable|enable|...]
set holddown-interval {integer}
set http-host {string}
set ip {user}
set max-connections {integer}
set monitor <name1>, <name2>, ...
set port {integer}
set status [active|standby|...]
set translate-host [enable|disable]
set type [ip|address]
set weight {integer}
next
end
set server-type [http|https|...]
set service <name1>, <name2>, ...
set src-filter <range1>, <range2>, ...
set src-vip-filter [disable|enable]
set srcintf-filter <interface-name1>, <interface-name2>, ...
set ssl-accept-ffdhe-groups [enable|disable]
set ssl-algorithm [high|medium|...]
set ssl-certificate <name1>, <name2>, ...
config ssl-cipher-suites
Description: SSL/TLS cipher suites acceptable from a client, ordered by
priority.
edit <priority>
set cipher [TLS-AES-128-GCM-SHA256|TLS-AES-256-GCM-SHA384|...]
set versions {option1}, {option2}, ...
next
end
set ssl-client-fallback [disable|enable]
set ssl-client-rekey-count {integer}
set ssl-client-renegotiation [allow|deny|...]
set ssl-client-session-state-max {integer}
set ssl-client-session-state-timeout {integer}
set ssl-client-session-state-type [disable|time|...]
set ssl-dh-bits [768|1024|...]
set ssl-hpkp [disable|enable|...]
set ssl-hpkp-age {integer}
set ssl-hpkp-backup {string}
set ssl-hpkp-include-subdomains [disable|enable]
set ssl-hpkp-primary {string}
set ssl-hpkp-report-uri {var-string}
set ssl-hsts [disable|enable]
set ssl-hsts-age {integer}
set ssl-hsts-include-subdomains [disable|enable]
set ssl-http-location-conversion [enable|disable]
set ssl-http-match-host [enable|disable]
set ssl-max-version [ssl-3.0|tls-1.0|...]
set ssl-min-version [ssl-3.0|tls-1.0|...]
set ssl-mode [half|full]
set ssl-pfs [require|deny|...]
set ssl-send-empty-frags [enable|disable]
set ssl-server-algorithm [high|medium|...]
config ssl-server-cipher-suites
Description: SSL/TLS cipher suites to offer to a server, ordered by priority.
edit <priority>
set cipher [TLS-AES-128-GCM-SHA256|TLS-AES-256-GCM-SHA384|...]
set versions {option1}, {option2}, ...
next
end
set ssl-server-max-version [ssl-3.0|tls-1.0|...]
set ssl-server-min-version [ssl-3.0|tls-1.0|...]
set ssl-server-renegotiation [enable|disable]
set ssl-server-session-state-max {integer}
set ssl-server-session-state-timeout {integer}
set ssl-server-session-state-type [disable|time|...]
set status [disable|enable]
set type [static-nat|load-balance|...]
set uuid {uuid}
set weblogic-server [disable|enable]
set websphere-server [disable|enable]
next
end

#### Parameters

config firewall vip
Parameter Description Type Size Default
add-nat46-route Enable/disable adding NAT46 route. option - enable
Option Description
disable Disable adding NAT46 route.
enable Enable adding NAT46 route.
arp-reply Enable to respond to ARP requests for this
virtual IP address. Enabled by default.
option - enable
Option Description
disable Disable ARP reply.
enable Enable ARP reply.
Parameter Description Type Size Default
color Color of icon on the GUI. integer Minimum
value: 0
Maximum
value: 32
0
comment Comment. var-string Maximum
length: 255
dns-mapping-ttl DNS mapping TTL. integer Minimum
value: 0
Maximum
value: 604800
0
extaddr <name> External FQDN address name.
Address name.
string Maximum
length: 79
extintf Interface connected to the source network
that receives the packets that will be
forwarded to the destination network.
string Maximum
length: 35
extip IP address or address range on the external
interface that you want to map to an address
or address range on the destination network.
user Not Specified
extport Incoming port number range that you want to
map to a port number range on the
destination network.
user Not Specified
gratuitous-arp-
interval
Enable to have the VIP send gratuitous
ARPs. 0=disabled. Set from 5 up to 8640000
seconds to enable.
integer Minimum
value: 5
Maximum
value:
8640000
0
gslb-domain-
name
Domain to use when integrating with
FortiGSLB.
string Maximum
length: 255
gslb-hostname Hostname to use within the configured
FortiGSLB domain.
string Maximum
length: 35
h2-support Enable/disable HTTP2 support. option - enable
Option Description
enable Enable HTTP2 support.
disable Disable HTTP2 support.
h3-support Enable/disable HTTP3/QUIC support. option - disable
Parameter Description Type Size Default
Option Description
enable Enable HTTP3/QUIC support.
disable Disable HTTP3/QUIC support.
http-cookie-age Time in minutes that client web browsers
should keep a cookie. Default is 60 minutes.
0 = no time limit.
integer Minimum
value: 0
Maximum
value: 525600
60
http-cookie-
domain
Domain that HTTP cookie persistence
should apply to.
string Maximum
length: 35
http-cookie-
domain-from-
host
Enable/disable use of HTTP cookie domain
from host field in HTTP.
option - disable
Option Description
disable Disable use of HTTP cookie domain from host field in HTTP (use http-
cooke-domain setting).
enable Enable use of HTTP cookie domain from host field in HTTP.
http-cookie-
generation
Generation of HTTP cookie to be accepted.
Changing invalidates all existing cookies.
integer Minimum
value: 0
Maximum
value:
4294967295
0
http-cookie-path Limit HTTP cookie persistence to the
specified path.
string Maximum
length: 35
http-cookie-share Control sharing of cookies across virtual
servers. Use of same-ip means a cookie from
one virtual server can be used by another.
Disable stops cookie sharing.
option - same-ip
Option Description
disable Only allow HTTP cookie to match this virtual server.
same-ip Allow HTTP cookie to match any virtual server with same IP.
http-ip-header For HTTP multiplexing, enable to add the
original client IP address in the XForwarded-
For HTTP header.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable adding HTTP header.
disable Disable adding HTTP header.
http-ip-header-
name
For HTTP multiplexing, enter a custom
HTTPS header name. The original client IP
address is added to this header. If empty, X-
Forwarded-For is used.
string Maximum
length: 35
http-multiplex Enable/disable HTTP multiplexing. option - disable
Option Description
enable Enable HTTP session multiplexing.
disable Disable HTTP session multiplexing.
http-multiplex-
max-concurrent-
request
Maximum number of concurrent requests
that a multiplex server can handle.
integer Minimum
value: 0
Maximum
value:
2147483647
0
http-multiplex-
max-request
Maximum number of requests that a
multiplex server can handle before
disconnecting sessions.
integer Minimum
value: 0
Maximum
value:
2147483647
0
http-multiplex-ttl Time-to-live for idle connections to servers. integer Minimum
value: 0
Maximum
value:
2147483647
15
http-redirect Enable/disable redirection of HTTP to
HTTPS.
option - disable
Option Description
enable Enable redirection of HTTP to HTTPS.
disable Disable redirection of HTTP to HTTPS.
https-cookie-
secure
Enable/disable verification that inserted
HTTPS cookies are secure.
option - disable
Parameter Description Type Size Default
Option Description
disable Do not mark cookie as secure, allow sharing between an HTTP and HTTPS
connection.
enable Mark inserted cookie as secure, cookie can only be used for HTTPS a
connection.
id Custom defined ID. integer Minimum
value: 0
Maximum
value: 65535
0
ipv6-mappedip Range of mapped IPv6 addresses. Specify
the start IPv6 address followed by a space
and the end IPv6 address.
user Not Specified
ipv6-mappedport IPv6 port number range on the destination
network to which the external port number
range is mapped.
user Not Specified
ldb-method Method used to distribute sessions to real
servers.
option - static
Option Description
static Distribute to server based on source IP.
round-robin Distribute to server based round robin order.
weighted Distribute to server based on weight.
least-session Distribute to server with lowest session count.
least-rtt Distribute to server with lowest Round-Trip-Time.
first-alive Distribute to the first server that is alive.
http-host Distribute to server based on host field in HTTP header.
mapped-addr Mapped FQDN address name. string Maximum
length: 79
mappedip
<range>
IP address or address range on the
destination network to which the external IP
address is mapped.
Mapped IP range.
string Maximum
length: 79
mappedport Port number range on the destination
network to which the external port number
range is mapped.
user Not Specified
Parameter Description Type Size Default
max-embryonic-
connections
Maximum number of incomplete
connections.
integer Minimum
value: 0
Maximum
value: 100000
1000
monitor <name> Name of the health check monitor to use
when polling to determine a virtual server's
connectivity status.
Health monitor name.
string Maximum
length: 79
name Virtual IP name. string Maximum
length: 79
nat-source-vip Enable/disable forcing the source NAT
mapped IP to the external IP for all traffic.
option - disable
Option Description
disable Force only the source NAT mapped IP to the external IP for traffic
egressing the external interface of the VIP.
enable Force the source NAT mapped IP to the external IP for all traffic.
nat44 Enable/disable NAT44. option - enable
Option Description
disable Disable NAT44.
enable Enable NAT44.
nat46 Enable/disable NAT46. option - disable
Option Description
disable Disable NAT46.
enable Enable NAT46.
one-click-gslb-
server
Enable/disable one click GSLB server
integration with FortiGSLB.
option - disable
Option Description
disable Disable integration with FortiGSLB.
enable Enable integration with FortiGSLB.
outlook-web-
access
Enable to add the Front-End-Https header
for Microsoft Outlook Web Access.
option - disable
Parameter Description Type Size Default
Option Description
disable Disable Outlook Web Access support.
enable Enable Outlook Web Access support.
persistence Configure how to make sure that clients
connect to the same server every time they
make a request that is part of the same
session.
option - none
Option Description
none None.
http-cookie HTTP cookie.
ssl-session-id SSL session ID.
portforward Enable/disable port forwarding. option - disable
Option Description
disable Disable port forward.
enable Enable port forward.
portmapping-
type
Port mapping type. option - 1-to-1
Option Description
1-to-1 One to one.
m-to-n Many to many.
protocol Protocol to use when forwarding packets. option - tcp
Option Description
tcp TCP.
udp UDP.
sctp SCTP.
icmp ICMP.
server-type Protocol to be load balanced by the virtual
server (also called the server load balance
virtual IP).
option -
Parameter Description Type Size Default
Option Description
http HTTP.
https HTTPS.
imaps IMAPS.
pop3s POP3S.
smtps SMTPS.
ssl SSL.
tcp TCP.
udp UDP.
ip IP.
service <name> Service name.
Service name.
string Maximum
length: 79
src-filter
<range>
Source address filter. Each address must be
either an IP/subnet (x.x.x.x/n) or a range
(x.x.x.x-y.y.y.y). Separate addresses with
spaces.
Source-filter range.
string Maximum
length: 79
src-vip-filter Enable/disable use of 'src-filter' to match
destinations for the reverse SNAT rule.
option - disable
Option Description
disable Match any destination for the reverse SNAT rule.
enable Match only destinations in 'src-filter' for the reverse SNAT rule.
srcintf-filter
<interface-
name>
Interfaces to which the VIP applies. Separate
the names with spaces.
Interface name.
string Maximum
length: 79
ssl-accept-ffdhe-
groups
Enable/disable FFDHE cipher suite for SSL
key exchange.
option - enable
Option Description
enable Accept FFDHE groups.
disable Do not accept FFDHE groups.
ssl-algorithm Permitted encryption algorithms for SSL
sessions according to encryption strength.
option - high
Parameter Description Type Size Default
Option Description
high High encryption. Allow only AES and ChaCha.
medium Medium encryption. Allow AES, ChaCha, 3DES, and RC4.
low Low encryption. Allow AES, ChaCha, 3DES, RC4, and DES.
custom Custom encryption. Use config ssl-cipher-suites to select the cipher suites
that are allowed.
ssl-certificate
<name>
Name of the certificate to use for SSL
handshake.
Certificate list.
string Maximum
length: 79
ssl-client-fallback Enable/disable support for preventing
Downgrade Attacks on client connections
(RFC 7507).
option - enable
Option Description
disable Disable.
enable Enable.
ssl-client-rekey-
count
Maximum length of data in MB before
triggering a client rekey (0 = disable).
integer Minimum
value: 200
Maximum
value:
1048576
0
ssl-client-
renegotiation
Allow, deny, or require secure renegotiation
of client sessions to comply with RFC 5746.
option - secure
Option Description
allow Allow a SSL client to renegotiate.
deny Abort any client initiated SSL re-negotiation attempt.
secure Abort any client initiated SSL re-negotiation attempt that does not use RFC
5746 Secure Renegotiation.
ssl-client-
session-state-
max
Maximum number of client to FortiGate SSL
session states to keep.
integer Minimum
value: 1
Maximum
value: 10000
1000
ssl-client-
session-state-
timeout
Number of minutes to keep client to
FortiGate SSL session state.
integer Minimum
value: 1
Maximum
value: 14400
30
Parameter Description Type Size Default
ssl-client-
session-state-
type
How to expire SSL sessions for the segment
of the SSL connection between the client and
the FortiGate.
option - both
Option Description
disable Do not keep session states.
time Expire session states after this many minutes.
count Expire session states when this maximum is reached.
both Expire session states based on time or count, whichever occurs first.
ssl-dh-bits Number of bits to use in the Diffie-Hellman
exchange for RSA encryption of SSL
sessions.
option - 2048
Option Description
768 768-bit Diffie-Hellman prime.
1024 1024-bit Diffie-Hellman prime.
1536 1536-bit Diffie-Hellman prime.
2048 2048-bit Diffie-Hellman prime.
3072 3072-bit Diffie-Hellman prime.
4096 4096-bit Diffie-Hellman prime.
ssl-hpkp Enable/disable including HPKP header in
response.
option - disable
Option Description
disable Do not add a HPKP header to each HTTP response.
enable Add a HPKP header to each a HTTP response.
report-only Add a HPKP Report-Only header to each HTTP response.
ssl-hpkp-age Number of seconds the client should honor
the HPKP setting.
integer Minimum
value: 60
Maximum
value:
157680000
5184000
ssl-hpkp-backup Certificate to generate backup HPKP pin
from.
string Maximum
length: 79
ssl-hpkp-include-
subdomains
Indicate that HPKP header applies to all
subdomains.
option - disable
Parameter Description Type Size Default
Option Description
disable HPKP header does not apply to subdomains.
enable HPKP header applies to subdomains.
ssl-hpkp-primary Certificate to generate primary HPKP pin
from.
string Maximum
length: 79
ssl-hpkp-report-
uri
URL to report HPKP violations to. var-string Maximum
length: 255
ssl-hsts Enable/disable including HSTS header in
response.
option - disable
Option Description
disable Do not add a HSTS header to each a HTTP response.
enable Add a HSTS header to each HTTP response.
ssl-hsts-age Number of seconds the client should honor
the HSTS setting.
integer Minimum
value: 60
Maximum
value:
157680000
5184000
ssl-hsts-include-
subdomains
Indicate that HSTS header applies to all
subdomains.
option - disable
Option Description
disable HSTS header does not apply to subdomains.
enable HSTS header applies to subdomains.
ssl-http-location-
conversion
Enable to replace HTTP with HTTPS in the
reply's Location HTTP header field.
option - disable
Option Description
enable Enable HTTP location conversion.
disable Disable HTTP location conversion.
ssl-http-match-
host
Enable/disable HTTP host matching for
location conversion.
option - enable
Option Description
enable Match HTTP host in response header.
disable Do not match HTTP host.
Parameter Description Type Size Default
ssl-max-version Highest SSL/TLS version acceptable from a
client.
option - tls-1.3
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.
ssl-min-version Lowest SSL/TLS version acceptable from a
client.
option - tls-1.1
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.
ssl-mode Apply SSL offloading between the client and
the FortiGate (half) or from the client to the
FortiGate and from the FortiGate to the
server (full).
option - half
Option Description
half Client to FortiGate SSL.
full Client to FortiGate and FortiGate to Server SSL.
ssl-pfs Select the cipher suites that can be used for
SSL perfect forward secrecy (PFS). Applies
to both client and server sessions.
option - require
Option Description
require Allow only Diffie-Hellman cipher-suites, so PFS is applied.
deny Allow only non-Diffie-Hellman cipher-suites, so PFS is not applied.
allow Allow use of any cipher suite so PFS may or may not be used depending on
the cipher suite selected.
Parameter Description Type Size Default
ssl-send-empty-
frags
Enable/disable sending empty fragments to
avoid CBC IV attacks (SSL 3.0 & TLS 1.0
only). May need to be disabled for
compatibility with older systems.
option - enable
Option Description
enable Send empty fragments.
disable Do not send empty fragments.
ssl-server-
algorithm
Permitted encryption algorithms for the
server side of SSL full mode sessions
according to encryption strength.
option - client
Option Description
high High encryption. Allow only AES and ChaCha.
medium Medium encryption. Allow AES, ChaCha, 3DES, and RC4.
low Low encryption. Allow AES, ChaCha, 3DES, RC4, and DES.
custom Custom encryption. Use ssl-server-cipher-suites to select the cipher suites
that are allowed.
client Use the same encryption algorithms for both client and server sessions.
ssl-server-max-
version
Highest SSL/TLS version acceptable from a
server. Use the client setting by default.
option - client
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.
client Use same value as client configuration.
ssl-server-min-
version
Lowest SSL/TLS version acceptable from a
server. Use the client setting by default.
option - client
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
Parameter Description Type Size Default
Option Description
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.
client Use same value as client configuration.
ssl-server-
renegotiation
Enable/disable secure renegotiation to
comply with RFC 5746.
option - enable
Option Description
enable Enable secure renegotiation.
disable Disable secure renegotiation.
ssl-server-
session-state-
max
Maximum number of FortiGate to Server SSL
session states to keep.
integer Minimum
value: 1
Maximum
value: 10000
100
ssl-server-
session-state-
timeout
Number of minutes to keep FortiGate to
Server SSL session state.
integer Minimum
value: 1
Maximum
value: 14400
60
ssl-server-
session-state-
type
How to expire SSL sessions for the segment
of the SSL connection between the server
and the FortiGate.
option - both
Option Description
disable Do not keep session states.
time Expire session states after this many minutes.
count Expire session states when this maximum is reached.
both Expire session states based on time or count, whichever occurs first.
status Enable/disable VIP. option - enable
Option Description
disable Disable the VIP.
enable Enable the VIP.
Parameter Description Type Size Default
type Configure a static NAT, load balance, server
load balance, access proxy, DNS translation,
or FQDN VIP.
option - static-nat
Option Description
static-nat Static NAT.
load-balance Load balance.
server-load-
balance
Server load balance.
dns-translation DNS translation.
fqdn Fully qualified domain name.
access-proxy Access proxy.
uuid Universally Unique Identifier (UUID;
automatically assigned but can be manually
reset).
uuid Not Specified 00000000-0000-
0000-0000-
000000000000
weblogic-server Enable to add an HTTP header to indicate
SSL offloading for a WebLogic server.
option - disable
Option Description
disable Do not add HTTP header indicating SSL offload for WebLogic server.
enable Add HTTP header indicating SSL offload for WebLogic server.
websphere-
server
Enable to add an HTTP header to indicate
SSL offloading for a WebSphere server.
option - disable
Option Description
disable Do not add HTTP header indicating SSL offload for WebSphere server.
enable Add HTTP header indicating SSL offload for WebSphere server.
config gslb-public-ips
Parameter Description Type Size Default
index Index of this public IP setting. integer Minimum
value: 0
Maximum
value:
4294967295
0
ip The publicly accessible IP address. ipv4-
address-
any
Not Specified 0.0.0.0
config quic
Parameter Description Type Size Default
ack-delay-
exponent
ACK delay exponent. integer Minimum
value: 1
Maximum
value: 20
3
active-
connection-id-
limit
Active connection ID limit. integer Minimum
value: 1
Maximum
value: 8
2
active-
migration
Enable/disable active migration. option - disable
Option Description
enable Enable active migration.
disable Disable active migration.
grease-quic-
bit
Enable/disable grease QUIC bit. option - enable
Option Description
enable Enable grease QUIC bit.
disable Disable grease QUIC bit.
max-ack-
delay
Maximum ACK delay in milliseconds. integer Minimum
value: 1
Maximum
value:
16383
25
max-
datagram-
frame-size
Maximum datagram frame size in bytes. integer Minimum
value: 1
Maximum
value: 1500
1500
max-idle-
timeout
Maximum idle timeout milliseconds. integer Minimum
value: 1
Maximum
value:
60000
30000
max-udp-
payload-size
Maximum UDP payload size in bytes. integer Minimum
value: 1200
Maximum
value: 1500
1500
config realservers
Parameter Description Type Size Default
address Dynamic address of the real server. string Maximum
length: 79
client-ip Only clients in this IP range can connect to this real
server.
user Not Specified
healthcheck Enable to check the responsiveness of the real
server before forwarding traffic.
option - vip
Option Description
disable Disable per server health check.
enable Enable per server health check.
vip Use health check defined in VIP.
holddown-
interval
Time in seconds that the system waits before re-
activating a previously down active server in the
active-standby mode. This is to prevent any flapping
issues.
integer Minimum
value: 30
Maximum
value: 65535
300
http-host HTTP server domain name in HTTP header. string Maximum
length: 63
id Real server ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
ip IP address of the real server. user Not Specified
max-
connections
Max number of active connections that can be
directed to the real server. When reached, sessions
are sent to other real servers.
integer Minimum
value: 0
Maximum
value:
2147483647
0
monitor
<name>
Name of the health check monitor to use when
polling to determine a virtual server's connectivity
status.
Health monitor name.
string Maximum
length: 79
port Port for communicating with the real server. Required
if port forwarding is enabled.
integer Minimum
value: 1
Maximum
value: 65535
0
Parameter Description Type Size Default
status Set the status of the real server to active so that it can
accept traffic, or on standby or disabled so no traffic
is sent.
option - active
Option Description
active Server status active.
standby Server status standby.
disable Server status disable.
translate-host Enable/disable translation of hostname/IP from
virtual server to real server.
option - enable
Option Description
enable Enable virtual hostname/IP translation.
disable Disable virtual hostname/IP translation.
type Type of address. option - ip
Option Description
ip Standard IPv4 address.
address Dynamic address object.
weight Weight of the real server. If weighted load balancing
is enabled, the server with the highest weight gets
more connections.
integer Minimum
value: 1
Maximum
value: 255
1
config ssl-cipher-suites
Parameter Description Type Size Default
cipher Cipher suite name. option -
Option Description
TLS-AES-128-
GCM-SHA256
Cipher suite TLS-AES-128-GCM-SHA256.
TLS-AES-256-
GCM-SHA384
Cipher suite TLS-AES-256-GCM-SHA384.
Parameter Description Type Size Default
Option Description
TLS-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-CHACHA20-POLY1305-SHA256.
TLS-ECDHE-
RSA-WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-ECDHE-
ECDSA-WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-DHE-RSA-
WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-DHE-RSA-
WITH-AES-128-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-AES-128-CBC-SHA.
TLS-DHE-RSA-
WITH-AES-256-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-AES-256-CBC-SHA.
TLS-DHE-RSA-
WITH-AES-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-AES-128-
GCM-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-128-GCM-SHA256.
TLS-DHE-RSA-
WITH-AES-256-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-256-CBC-SHA256.
TLS-DHE-RSA-
WITH-AES-256-
GCM-SHA384
Cipher suite TLS-DHE-RSA-WITH-AES-256-GCM-SHA384.
Parameter Description Type Size Default
Option Description
TLS-DHE-DSS-
WITH-AES-128-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-AES-128-CBC-SHA.
TLS-DHE-DSS-
WITH-AES-256-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-AES-256-CBC-SHA.
TLS-DHE-DSS-
WITH-AES-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-AES-128-
GCM-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-128-GCM-SHA256.
TLS-DHE-DSS-
WITH-AES-256-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-256-CBC-SHA256.
TLS-DHE-DSS-
WITH-AES-256-
GCM-SHA384
Cipher suite TLS-DHE-DSS-WITH-AES-256-GCM-SHA384.
TLS-ECDHE-
RSA-WITH-AES-
128-CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA.
TLS-ECDHE-
RSA-WITH-AES-
128-CBC-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256.
TLS-ECDHE-
RSA-WITH-AES-
128-GCM-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256.
TLS-ECDHE-
RSA-WITH-AES-
256-CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA.
TLS-ECDHE-
RSA-WITH-AES-
256-CBC-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384.
Parameter Description Type Size Default
Option Description
TLS-ECDHE-
RSA-WITH-AES-
256-GCM-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384.
TLS-ECDHE-
ECDSA-WITH-
AES-128-CBC-
SHA
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA.
TLS-ECDHE-
ECDSA-WITH-
AES-128-CBC-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256.
TLS-ECDHE-
ECDSA-WITH-
AES-128-GCM-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256.
TLS-ECDHE-
ECDSA-WITH-
AES-256-CBC-
SHA
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA.
TLS-ECDHE-
ECDSA-WITH-
AES-256-CBC-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384.
TLS-ECDHE-
ECDSA-WITH-
AES-256-GCM-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384.
TLS-RSA-WITH-
AES-128-CBC-
SHA
Cipher suite TLS-RSA-WITH-AES-128-CBC-SHA.
TLS-RSA-WITH-
AES-256-CBC-
SHA
Cipher suite TLS-RSA-WITH-AES-256-CBC-SHA.
TLS-RSA-WITH-
AES-128-CBC-
SHA256
Cipher suite TLS-RSA-WITH-AES-128-CBC-SHA256.
Parameter Description Type Size Default
Option Description
TLS-RSA-WITH-
AES-128-GCM-
SHA256
Cipher suite TLS-RSA-WITH-AES-128-GCM-SHA256.
TLS-RSA-WITH-
AES-256-CBC-
SHA256
Cipher suite TLS-RSA-WITH-AES-256-CBC-SHA256.
TLS-RSA-WITH-
AES-256-GCM-
SHA384
Cipher suite TLS-RSA-WITH-AES-256-GCM-SHA384.
TLS-RSA-WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-RSA-WITH-CAMELLIA-128-CBC-SHA.
TLS-RSA-WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-RSA-WITH-CAMELLIA-256-CBC-SHA.
TLS-RSA-WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256.
TLS-RSA-WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-RSA-
WITH-3DES-
EDE-CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA.
TLS-DHE-RSA-
WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA.
TLS-DHE-DSS-
WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-DSS-RSA-WITH-CAMELLIA-128-CBC-SHA.
TLS-DHE-RSA-
WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-DHE-DSS-
WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA.
TLS-DHE-RSA-
WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-DSS-
WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-RSA-
WITH-SEED-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-SEED-CBC-SHA.
TLS-DHE-DSS-
WITH-SEED-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-SEED-CBC-SHA.
TLS-DHE-RSA-
WITH-ARIA-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-ARIA-256-
CBC-SHA384
Cipher suite TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384.
TLS-DHE-DSS-
WITH-ARIA-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-ARIA-256-
CBC-SHA384
Cipher suite TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384.
Parameter Description Type Size Default
Option Description
TLS-RSA-WITH-
SEED-CBC-SHA
Cipher suite TLS-RSA-WITH-SEED-CBC-SHA.
TLS-RSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-RSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-RSA-WITH-ARIA-256-CBC-SHA384.
TLS-ECDHE-
RSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-ECDHE-
RSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384.
TLS-ECDHE-
ECDSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC_SHA256.
TLS-ECDHE-
ECDSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC_SHA384.
TLS-ECDHE-
RSA-WITH-RC4-
128-SHA
Cipher suite TLS-ECDHE-RSA-WITH-RC4-128-SHA.
TLS-ECDHE-
RSA-WITH-
3DES-EDE-
CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA.
TLS-DHE-DSS-
WITH-3DES-
EDE-CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA.
TLS-RSA-WITH-
3DES-EDE-
CBC-SHA
Cipher suite TLS-RSA-WITH-3DES-EDE-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-RSA-WITH-
RC4-128-MD5
Cipher suite TLS-RSA-WITH-RC4-128-MD5.
TLS-RSA-WITH-
RC4-128-SHA
Cipher suite TLS-RSA-WITH-RC4-128-SHA.
TLS-DHE-RSA-
WITH-DES-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-DES-CBC-SHA.
TLS-DHE-DSS-
WITH-DES-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-DES-CBC-SHA.
TLS-RSA-WITH-
DES-CBC-SHA
Cipher suite TLS-RSA-WITH-DES-CBC-SHA.
priority SSL/TLS cipher suites priority. integer Minimum
value: 0
Maximum
value:
4294967295
0
versions SSL/TLS versions that the cipher suite can be used
with.
option - ssl-3.0 tls-
1.0 tls-1.1
tls-1.2 tls-
1.3
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.
config ssl-server-cipher-suites
Parameter Description Type Size Default
cipher Cipher suite name. option -
Parameter Description Type Size Default
Option Description
TLS-AES-128-
GCM-SHA256
Cipher suite TLS-AES-128-GCM-SHA256.
TLS-AES-256-
GCM-SHA384
Cipher suite TLS-AES-256-GCM-SHA384.
TLS-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-CHACHA20-POLY1305-SHA256.
TLS-ECDHE-
RSA-WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-ECDHE-
ECDSA-WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-DHE-RSA-
WITH-
CHACHA20-
POLY1305-
SHA256
Cipher suite TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256.
TLS-DHE-RSA-
WITH-AES-128-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-AES-128-CBC-SHA.
TLS-DHE-RSA-
WITH-AES-256-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-AES-256-CBC-SHA.
TLS-DHE-RSA-
WITH-AES-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-AES-128-
GCM-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-128-GCM-SHA256.
TLS-DHE-RSA-
WITH-AES-256-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-AES-256-CBC-SHA256.
Parameter Description Type Size Default
Option Description
TLS-DHE-RSA-
WITH-AES-256-
GCM-SHA384
Cipher suite TLS-DHE-RSA-WITH-AES-256-GCM-SHA384.
TLS-DHE-DSS-
WITH-AES-128-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-AES-128-CBC-SHA.
TLS-DHE-DSS-
WITH-AES-256-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-AES-256-CBC-SHA.
TLS-DHE-DSS-
WITH-AES-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-AES-128-
GCM-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-128-GCM-SHA256.
TLS-DHE-DSS-
WITH-AES-256-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-AES-256-CBC-SHA256.
TLS-DHE-DSS-
WITH-AES-256-
GCM-SHA384
Cipher suite TLS-DHE-DSS-WITH-AES-256-GCM-SHA384.
TLS-ECDHE-
RSA-WITH-AES-
128-CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA.
TLS-ECDHE-
RSA-WITH-AES-
128-CBC-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256.
TLS-ECDHE-
RSA-WITH-AES-
128-GCM-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256.
TLS-ECDHE-
RSA-WITH-AES-
256-CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-ECDHE-
RSA-WITH-AES-
256-CBC-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384.
TLS-ECDHE-
RSA-WITH-AES-
256-GCM-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384.
TLS-ECDHE-
ECDSA-WITH-
AES-128-CBC-
SHA
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA.
TLS-ECDHE-
ECDSA-WITH-
AES-128-CBC-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256.
TLS-ECDHE-
ECDSA-WITH-
AES-128-GCM-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256.
TLS-ECDHE-
ECDSA-WITH-
AES-256-CBC-
SHA
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA.
TLS-ECDHE-
ECDSA-WITH-
AES-256-CBC-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384.
TLS-ECDHE-
ECDSA-WITH-
AES-256-GCM-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384.
TLS-RSA-WITH-
AES-128-CBC-
SHA
Cipher suite TLS-RSA-WITH-AES-128-CBC-SHA.
TLS-RSA-WITH-
AES-256-CBC-
SHA
Cipher suite TLS-RSA-WITH-AES-256-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-RSA-WITH-
AES-128-CBC-
SHA256
Cipher suite TLS-RSA-WITH-AES-128-CBC-SHA256.
TLS-RSA-WITH-
AES-128-GCM-
SHA256
Cipher suite TLS-RSA-WITH-AES-128-GCM-SHA256.
TLS-RSA-WITH-
AES-256-CBC-
SHA256
Cipher suite TLS-RSA-WITH-AES-256-CBC-SHA256.
TLS-RSA-WITH-
AES-256-GCM-
SHA384
Cipher suite TLS-RSA-WITH-AES-256-GCM-SHA384.
TLS-RSA-WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-RSA-WITH-CAMELLIA-128-CBC-SHA.
TLS-RSA-WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-RSA-WITH-CAMELLIA-256-CBC-SHA.
TLS-RSA-WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256.
TLS-RSA-WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-RSA-
WITH-3DES-
EDE-CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA.
TLS-DHE-RSA-
WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA.
TLS-DHE-DSS-
WITH-
CAMELLIA-128-
CBC-SHA
Cipher suite TLS-DSS-RSA-WITH-CAMELLIA-128-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-DHE-RSA-
WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA.
TLS-DHE-DSS-
WITH-
CAMELLIA-256-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA.
TLS-DHE-RSA-
WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-
CAMELLIA-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-DSS-
WITH-
CAMELLIA-256-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256.
TLS-DHE-RSA-
WITH-SEED-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-SEED-CBC-SHA.
TLS-DHE-DSS-
WITH-SEED-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-SEED-CBC-SHA.
TLS-DHE-RSA-
WITH-ARIA-128-
CBC-SHA256
Cipher suite TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-DHE-RSA-
WITH-ARIA-256-
CBC-SHA384
Cipher suite TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384.
Parameter Description Type Size Default
Option Description
TLS-DHE-DSS-
WITH-ARIA-128-
CBC-SHA256
Cipher suite TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256.
TLS-DHE-DSS-
WITH-ARIA-256-
CBC-SHA384
Cipher suite TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384.
TLS-RSA-WITH-
SEED-CBC-SHA
Cipher suite TLS-RSA-WITH-SEED-CBC-SHA.
TLS-RSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-RSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-RSA-WITH-ARIA-256-CBC-SHA384.
TLS-ECDHE-
RSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256.
TLS-ECDHE-
RSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384.
TLS-ECDHE-
ECDSA-WITH-
ARIA-128-CBC-
SHA256
Cipher suite TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC_SHA256.
TLS-ECDHE-
ECDSA-WITH-
ARIA-256-CBC-
SHA384
Cipher suite TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC_SHA384.
TLS-ECDHE-
RSA-WITH-RC4-
128-SHA
Cipher suite TLS-ECDHE-RSA-WITH-RC4-128-SHA.
TLS-ECDHE-
RSA-WITH-
3DES-EDE-
CBC-SHA
Cipher suite TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA.
Parameter Description Type Size Default
Option Description
TLS-DHE-DSS-
WITH-3DES-
EDE-CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA.
TLS-RSA-WITH-
3DES-EDE-
CBC-SHA
Cipher suite TLS-RSA-WITH-3DES-EDE-CBC-SHA.
TLS-RSA-WITH-
RC4-128-MD5
Cipher suite TLS-RSA-WITH-RC4-128-MD5.
TLS-RSA-WITH-
RC4-128-SHA
Cipher suite TLS-RSA-WITH-RC4-128-SHA.
TLS-DHE-RSA-
WITH-DES-
CBC-SHA
Cipher suite TLS-DHE-RSA-WITH-DES-CBC-SHA.
TLS-DHE-DSS-
WITH-DES-
CBC-SHA
Cipher suite TLS-DHE-DSS-WITH-DES-CBC-SHA.
TLS-RSA-WITH-
DES-CBC-SHA
Cipher suite TLS-RSA-WITH-DES-CBC-SHA.
priority SSL/TLS cipher suites priority. integer Minimum
value: 0
Maximum
value:
4294967295
0
versions SSL/TLS versions that the cipher suite can be used
with.
option - ssl-3.0 tls-
1.0 tls-1.1
tls-1.2 tls-
1.3
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.

### config firewall vip6

Configure virtual IP for IPv6.

---

## config_firewall_vipgrp.md

# config firewall vipgrp

> Source: `config firewall vipgrp.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
versions SSL/TLS versions that the cipher suite can be used
with.
option - ssl-3.0 tls-
1.0 tls-1.1
tls-1.2 tls-
1.3
Option Description
ssl-3.0 SSL 3.0.
tls-1.0 TLS 1.0.
tls-1.1 TLS 1.1.
tls-1.2 TLS 1.2.
tls-1.3 TLS 1.3.

### config firewall vipgrp

Configure IPv4 virtual IP groups.

#### Syntax

config firewall vipgrp
Description: Configure IPv4 virtual IP groups.
edit <name>
set color {integer}
set comments {var-string}
set interface {string}
set member <name1>, <name2>, ...
set uuid {uuid}
next
end

#### Parameters

config firewall vipgrp
Parameter Description Type Size Default
color Integer value to determine the color of the icon in
the GUI.
integer Minimum
value: 0
Maximum
value: 32
0
comments Comment. var-string Maximum
length: 255
interface Interface. string Maximum
length: 35
member
<name>
Member VIP objects of the group (Separate
multiple objects with a space).
VIP name.
string Maximum
length: 79
Parameter Description Type Size Default
name VIP group name. string Maximum
length: 79
uuid Universally Unique Identifier (UUID; automatically
assigned but can be manually reset).
uuid Not
Specified
00000000-0000-
0000-0000-
000000000000

### config firewall vipgrp6

Configure IPv6 virtual IP groups.

#### Syntax

config firewall vipgrp6
Description: Configure IPv6 virtual IP groups.
edit <name>
set color {integer}
set comments {var-string}
set member <name1>, <name2>, ...
set uuid {uuid}
next
end

#### Parameters

config firewall vipgrp6
Parameter Description Type Size Default
color Integer value to determine the color of the icon in
the GUI.
integer Minimum
value: 0
Maximum
value: 32
0
comments Comment. var-string Maximum
length: 255
member
<name>
Member VIP objects of the group (Separate
multiple objects with a space).
IPv6 VIP name.
string Maximum
length: 79
name IPv6 VIP group name. string Maximum
length: 79
uuid Universally Unique Identifier (UUID; automatically
assigned but can be manually reset).
uuid Not
Specified
00000000-0000-
0000-0000-
000000000000

### config firewall wildcard-fqdn custom

Config global/VDOM Wildcard FQDN address.

---

## config_ips_sensor.md

# config ips sensor

> Source: `config ips sensor.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

config metadata
Parameter Description Type Size Default
id ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
metaid Meta ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
valueid Value ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0

### config ips sensor

Configure IPS sensor.

#### Syntax

config ips sensor
Description: Configure IPS sensor.
edit <name>
set block-malicious-url [disable|enable]
set comment {var-string}
config entries
Description: IPS sensor filter.
edit <id>
set action [pass|block|...]
set application {user}
set cve <cve-entry1>, <cve-entry2>, ...
set default-action [all|pass|...]
set default-status [all|enable|...]
config exempt-ip
Description: Traffic from selected source or destination IP addresses is
exempt from this signature.
edit <id>
set dst-ip {ipv4-classnet}
set src-ip {ipv4-classnet}
next
end
set last-modified {user}
set location {user}
set log [disable|enable]
set log-attack-context [disable|enable]
set log-packet [disable|enable]
set os {user}
set protocol {user}
set quarantine [none|attacker]
set quarantine-expiry {user}
set quarantine-log [disable|enable]
set rate-count {integer}
set rate-duration {integer}
set rate-mode [periodical|continuous]
set rate-track [none|src-ip|...]
set rule <id1>, <id2>, ...
set severity {user}
set status [disable|enable|...]
set vuln-type <id1>, <id2>, ...
next
end
set extended-log [enable|disable]
set replacemsg-group {string}
set scan-botnet-connections [disable|block|...]
next
end

#### Parameters

config ips sensor
Parameter Description Type Size Default
block-
malicious-url
Enable/disable malicious URL blocking. option - disable
Option Description
disable Disable malicious URL blocking.
enable Enable malicious URL blocking.
comment Comment. var-string Maximum
length: 255
extended-log Enable/disable extended logging. option - disable
Option Description
enable Enable setting.
disable Disable setting.
name Sensor name. string Maximum
length: 35
replacemsg-
group
Replacement message group. string Maximum
length: 35
scan-botnet-
connections
Block or monitor connections to Botnet servers, or
disable Botnet scanning.
option - disable
Parameter Description Type Size Default
Option Description
disable Do not scan connections to botnet servers.
block Block connections to botnet servers.
monitor Log connections to botnet servers.
config entries
Parameter Description Type Size Default
action Action taken with traffic in which signatures are
detected.
option - default
Option Description
pass Pass or allow matching traffic.
block Block or drop matching traffic.
reset Reset sessions for matching traffic.
default Pass or drop matching traffic, depending on the default action of the signature.
application Operating systems to be protected. Use all for every
application and other for unlisted application.
user Not Specified all
cve <cve-
entry>
List of CVE IDs of the signatures to add to the
sensor.
CVE IDs or CVE wildcards.
string Maximum
length: 19
default-action Signature default action filter. option - all
Option Description
all Selects signatures with any default action.
pass Selects signatures with default action 'pass'.
block Selects signatures with default action 'block'.
default-status Signature default status filter. option - all
Option Description
all Selects signatures with any default status.
enable Selects signatures enabled by default.
disable Selects signatures disabled by default.
Parameter Description Type Size Default
id Rule ID in IPS database. integer Minimum
value: 0
Maximum
value:
4294967295
0
last-modified Filter by signature last modified date. Formats:
before <date>, after <date>, between <start-date>
<end-date>.
user Not Specified
location Protect client or server traffic. user Not Specified all
log Enable/disable logging of signatures included in
filter.
option - enable
Option Description
disable Disable logging of selected rules.
enable Enable logging of selected rules.
log-attack-
context
Enable/disable logging of attack context: URL
buffer, header buffer, body buffer, packet buffer.
option - disable
Option Description
disable Disable logging of detailed attack context.
enable Enable logging of detailed attack context.
log-packet Enable/disable packet logging. Enable to save the
packet that triggers the filter. You can download the
packets in pcap format for diagnostic use.
option - disable
Option Description
disable Disable packet logging of selected rules.
enable Enable packet logging of selected rules.
os Operating systems to be protected. Use all for every
operating system and other for unlisted operating
systems.
user Not Specified all
protocol Protocols to be examined. Use all for every protocol
and other for unlisted protocols.
user Not Specified all
quarantine Quarantine method. option - none
Option Description
none Quarantine is disabled.
Parameter Description Type Size Default
Option Description
attacker Block all traffic sent from attacker's IP address. The attacker's IP address is
also added to the banned user list. The target's address is not affected.
quarantine-
expiry
Duration of quarantine. Requires quarantine set to
attacker.
user Not Specified 5m
quarantine-

## log

Enable/disable quarantine logging. option - enable
Option Description
disable Disable quarantine logging.
enable Enable quarantine logging.
rate-count Count of the rate. integer Minimum
value: 0
Maximum
value: 65535
0
rate-duration Duration (sec) of the rate. integer Minimum
value: 1
Maximum
value: 65535
60
rate-mode Rate limit mode. option - continuous
Option Description
periodical Allow configured number of packets every rate-duration.
continuous Block packets once the rate is reached.
rate-track Track the packet protocol field. option - none
Option Description
none none
src-ip Source IP.
dest-ip Destination IP.
dhcp-client-mac DHCP client.
dns-domain DNS domain.
Parameter Description Type Size Default
rule <id> Identifies the predefined or custom IPS signatures
to add to the sensor.
Rule IPS.
integer Minimum
value: 0
Maximum
value:
4294967295
severity Relative severity of the signature, from info to
critical. Log messages generated by the signature
include the severity.
user Not Specified all
status Status of the signatures included in filter. Only those
filters with a status to enable are used.
option - default
Option Description
disable Disable status of selected rules.
enable Enable status of selected rules.
default Default.
vuln-type
<id>
List of signature vulnerability types to filter by.
Vulnerability type ID.
integer Minimum
value: 0
Maximum
value:
4294967295
config exempt-ip
Parameter Description Type Size Default
dst-ip Destination IP address and netmask (applies to
packet matching the signature).
ipv4-
classnet
Not Specified 0.0.0.0
0.0.0.0
id Exempt IP ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
src-ip Source IP address and netmask (applies to packet
matching the signature).
ipv4-
classnet
Not Specified 0.0.0.0
0.0.0.0

### config ips settings

Configure IPS VDOM parameter.

#### Syntax

config ips settings
Description: Configure IPS VDOM parameter.
set ips-packet-quota {integer}
set packet-log-history {integer}

---

## config_router_static.md

# config router static

> Source: `config router static.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
set-weight BGP weight for routing table. integer Minimum
value: 0
Maximum
value:
4294967295

### config router setting

Configure router settings.

#### Syntax

config router setting
Description: Configure router settings.
set hostname {string}
set show-filter {string}
end

#### Parameters

config router setting
Parameter Description Type Size Default
hostname Hostname for this virtual domain router. string Maximum
length: 14
show-filter Prefix-list as filter for showing routes. string Maximum
length: 35

### config router static

Configure IPv4 static routing tables.

#### Syntax

config router static
Description: Configure IPv4 static routing tables.
edit <seq-num>
set bfd [enable|disable]
set blackhole [enable|disable]
set comment {var-string}
set device {string}
set distance {integer}
set dst {ipv4-classnet}
set dstaddr {string}
set dynamic-gateway [enable|disable]
set gateway {ipv4-address}
set internet-service {integer}
set internet-service-custom {string}
set link-monitor-exempt [enable|disable]
set preferred-source {ipv4-address}
set priority {integer}
set sdwan-zone <name1>, <name2>, ...
set src {ipv4-classnet}
set status [enable|disable]
set tag {integer}
set vrf {integer}
set weight {integer}
next
end

#### Parameters

config router static
Parameter Description Type Size Default
bfd Enable/disable Bidirectional Forwarding Detection
(BFD).
option - disable
Option Description
enable Enable Bidirectional Forwarding Detection (BFD).
disable Disable Bidirectional Forwarding Detection (BFD).
blackhole Enable/disable black hole. option - disable
Option Description
enable Enable black hole.
disable Disable black hole.
comment Optional comments. var-string Maximum
length: 255
device Gateway out interface or tunnel. string Maximum
length: 35
distance Administrative distance. integer Minimum
value: 1
Maximum
value: 255
10
dst Destination IP and mask for this route. ipv4-
classnet
Not Specified 0.0.0.0
0.0.0.0
dstaddr Name of firewall address or address group. string Maximum
length: 79
dynamic-
gateway
Enable use of dynamic gateway retrieved from a
DHCP or PPP server.
option - disable
Option Description
enable Enable dynamic gateway.
disable Disable dynamic gateway.
Parameter Description Type Size Default
gateway Gateway IP for this route. ipv4-
address
Not Specified 0.0.0.0
internet-
service
Application ID in the Internet service database. integer Minimum
value: 0
Maximum
value:
4294967295
0
internet-
service-
custom
Application name in the Internet service custom
database.
string Maximum
length: 64
link-monitor-
exempt
Enable/disable withdrawal of this static route when
link monitor or health check is down.
option - disable
Option Description
enable Keep this static route when link monitor or health check is down.
disable Withdraw this static route when link monitor or health check is down. (default)
preferred-
source
Preferred source IP for this route. ipv4-
address
Not Specified 0.0.0.0
priority Administrative priority. integer Minimum
value: 1
Maximum
value: 65535
1
sdwan-zone
<name>
Choose SD-WAN Zone.
SD-WAN zone name.
string Maximum
length: 79
seq-num Sequence number. integer Minimum
value: 0
Maximum
value:
4294967295
0
src Source prefix for this route. ipv4-
classnet
Not Specified 0.0.0.0
0.0.0.0
status Enable/disable this static route. option - enable
Option Description
enable Enable static route.
disable Disable static route.
Parameter Description Type Size Default
tag Route tag. integer Minimum
value: 0
Maximum
value:
4294967295
0
vrf Virtual Routing Forwarding ID. integer Minimum
value: 0
Maximum
value: 251
unspecified
weight Administrative weight. integer Minimum
value: 0
Maximum
value: 255
0

### config router static6

Configure IPv6 static routing tables.

#### Syntax

config router static6
Description: Configure IPv6 static routing tables.
edit <seq-num>
set bfd [enable|disable]
set blackhole [enable|disable]
set comment {var-string}
set device {string}
set devindex {integer}
set distance {integer}
set dst {ipv6-network}
set dstaddr {string}
set dynamic-gateway [enable|disable]
set gateway {ipv6-address}
set link-monitor-exempt [enable|disable]
set priority {integer}
set sdwan-zone <name1>, <name2>, ...
set status [enable|disable]
set vrf {integer}
set weight {integer}
next
end

#### Parameters

config router static6
Parameter Description Type Size Default
bfd Enable/disable Bidirectional Forwarding Detection
(BFD).
option - disable

---

## config_system_accprofile.md

# config system accprofile

> Source: `config system accprofile.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
init-string Init string in hexadecimal format (even length). string Maximum
length: 127
model MODEM model name. string Maximum
length: 35
modeswitch-
string
USB modeswitch arguments. For example: '-v 1410 -
p 9030 -V 1410 -P 9032 -u 3'.
string Maximum
length: 127
product-id USB product ID in hexadecimal format (0000-ffff). user Not Specified
vendor MODEM vendor name. string Maximum
length: 35
vendor-id USB vendor ID in hexadecimal format (0000-ffff). user Not Specified

### config system accprofile

Configure access profiles for system administrators.

#### Syntax

config system accprofile
Description: Configure access profiles for system administrators.
edit <name>
set admintimeout {integer}
set admintimeout-override [enable|disable]
set authgrp [none|read|...]
set cli-config [enable|disable]
set cli-diagnose [enable|disable]
set cli-exec [enable|disable]
set cli-get [enable|disable]
set cli-show [enable|disable]
set comments {var-string}
set ftviewgrp [none|read|...]
set fwgrp [none|read|...]
config fwgrp-permission
Description: Custom firewall permission.
set address [none|read|...]
set others [none|read|...]
set policy [none|read|...]
set schedule [none|read|...]
set service [none|read|...]
end
set loggrp [none|read|...]
config loggrp-permission
Description: Custom Log & Report permission.
set config [none|read|...]
set data-access [none|read|...]
set report-access [none|read|...]
set threat-weight [none|read|...]
end
set netgrp [none|read|...]
config netgrp-permission
Description: Custom network permission.
set cfg [none|read|...]
set packet-capture [none|read|...]
set route-cfg [none|read|...]
end
set scope [vdom|global]
set secfabgrp [none|read|...]
set sysgrp [none|read|...]
config sysgrp-permission
Description: Custom system permission.
set admin [none|read|...]
set cfg [none|read|...]
set mnt [none|read|...]
set upd [none|read|...]
end
set system-execute-ssh [enable|disable]
set system-execute-telnet [enable|disable]
set utmgrp [none|read|...]
config utmgrp-permission
Description: Custom Security Profile permissions.
set antivirus [none|read|...]
set application-control [none|read|...]
set casb [none|read|...]
set dlp [none|read|...]
set dnsfilter [none|read|...]
set emailfilter [none|read|...]
set endpoint-control [none|read|...]
set file-filter [none|read|...]
set icap [none|read|...]
set ips [none|read|...]
set videofilter [none|read|...]
set virtual-patch [none|read|...]
set voip [none|read|...]
set waf [none|read|...]
set webfilter [none|read|...]
end
set vpngrp [none|read|...]
set wanoptgrp [none|read|...]
set wifi [none|read|...]
next
end

#### Parameters

config system accprofile
Parameter Description Type Size Default
admintimeout Administrator timeout for this access profile. integer Minimum
value: 1
Maximum
value: 480
10
admintimeout-
override
Enable/disable overriding the global administrator idle
timeout.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable overriding the global administrator idle timeout.
disable Disable overriding the global administrator idle timeout.
authgrp Administrator access to Users and Devices. option - none
Option Description
none No access.
read Read access.
read-write Read/write access.
cli-config Enable/disable permission to run config commands. option - disable
Option Description
enable Enable permission to run config commands.
disable Disable permission to run config commands.
cli-diagnose Enable/disable permission to run diagnostic
commands.
option - disable
Option Description
enable Enable permission to run diagnostic commands.
disable Disable permission to run diagnostic commands.
cli-exec Enable/disable permission to run execute commands. option - disable
Option Description
enable Enable permission to run execute commands.
disable Disable permission to run execute commands.
cli-get Enable/disable permission to run get commands. option - disable
Option Description
enable Enable permission to run get commands.
disable Disable permission to run get commands.
cli-show Enable/disable permission to run show commands. option - disable
Option Description
enable Enable permission to run show commands.

---

## config_system_admin.md

# config system admin

> Source: `config system admin.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
email Account email. string Maximum
length: 255
id Account id. string Maximum
length: 255
privatekey Account Private Key. string Maximum
length: 8191
status Account status. string Maximum
length: 127
url Account url. string Maximum
length: 511

### config system admin

Configure admin users.

#### Syntax

config system admin
Description: Configure admin users.
edit <name>
set accprofile {string}
set accprofile-override [enable|disable]
set allow-remove-admin-session [enable|disable]
set comments {var-string}
set email-to {string}
set force-password-change [enable|disable]
set fortitoken {string}
set guest-auth [disable|enable]
set guest-lang {string}
set guest-usergroups <name1>, <name2>, ...
set ip6-trusthost1 {ipv6-prefix}
set ip6-trusthost10 {ipv6-prefix}
set ip6-trusthost2 {ipv6-prefix}
set ip6-trusthost3 {ipv6-prefix}
set ip6-trusthost4 {ipv6-prefix}
set ip6-trusthost5 {ipv6-prefix}
set ip6-trusthost6 {ipv6-prefix}
set ip6-trusthost7 {ipv6-prefix}
set ip6-trusthost8 {ipv6-prefix}
set ip6-trusthost9 {ipv6-prefix}
set password {password-2}
set password-expire {user}
set peer-auth [enable|disable]
set peer-group {string}
set remote-auth [enable|disable]
set remote-group {string}
set schedule {string}
set sms-custom-server {string}
set sms-phone {string}
set sms-server [fortiguard|custom]
set ssh-certificate {string}
set ssh-public-key1 {user}
set ssh-public-key2 {user}
set ssh-public-key3 {user}
set trusthost1 {ipv4-classnet}
set trusthost10 {ipv4-classnet}
set trusthost2 {ipv4-classnet}
set trusthost3 {ipv4-classnet}
set trusthost4 {ipv4-classnet}
set trusthost5 {ipv4-classnet}
set trusthost6 {ipv4-classnet}
set trusthost7 {ipv4-classnet}
set trusthost8 {ipv4-classnet}
set trusthost9 {ipv4-classnet}
set two-factor [disable|fortitoken|...]
set two-factor-authentication [fortitoken|email|...]
set two-factor-notification [email|sms]
set vdom <name1>, <name2>, ...
set vdom-override [enable|disable]
set wildcard [enable|disable]
next
end

#### Parameters

config system admin
Parameter Description Type Size Default
accprofile Access profile for this administrator. Access profiles
control administrator access to FortiGate features.
string Maximum
length: 35
accprofile-
override
Enable to use the name of an access profile
provided by the remote authentication server to
control the FortiGate features that this administrator
can access.
option - disable
Option Description
enable Enable access profile override.
disable Disable access profile override.
allow-remove-
admin-session
Enable/disable allow admin session to be removed
by privileged admin users.
option - enable
Option Description
enable Enable allow-remove option.
disable Disable allow-remove option.
comments Comment. var-string Maximum
length: 255
email-to This administrator's email address. string Maximum
length: 63
Parameter Description Type Size Default
force-password-
change
Enable/disable force password change on next
login.
option - disable
Option Description
enable Enable force password change on next login.
disable Disable force password change on next login.
fortitoken This administrator's FortiToken serial number. string Maximum
length: 16
guest-auth Enable/disable guest authentication. option - disable
Option Description
disable Disable guest authentication.
enable Enable guest authentication.
guest-lang Guest management portal language. string Maximum
length: 35
guest-
usergroups
<name>
Select guest user groups.
Select guest user groups.
string Maximum
length: 79
ip6-trusthost1 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost10 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost2 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost3 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost4 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost5 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
Parameter Description Type Size Default
ip6-trusthost6 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost7 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost8 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
ip6-trusthost9 Any IPv6 address from which the administrator can
connect to the FortiGate unit. Default allows access
from any IPv6 address.
ipv6-prefix Not
Specified
::/0
name User name. string Maximum
length: 64
password Admin user password. password-2 Not
Specified
password-expire Password expire time. user Not
Specified
peer-auth Set to enable peer certificate authentication (for
HTTPS admin access).
option - disable
Option Description
enable Enable peer.
disable Disable peer.
peer-group Name of peer group defined under config user group
which has PKI members. Used for peer certificate
authentication (for HTTPS admin access).
string Maximum
length: 35
remote-auth Enable/disable authentication using a remote
RADIUS, LDAP, or TACACS+ server.
option - disable
Option Description
enable Enable remote authentication.
disable Disable remote authentication.
remote-group User group name used for remote auth. string Maximum
length: 35
schedule Firewall schedule used to restrict when the
administrator can log in. No schedule means no
restrictions.
string Maximum
length: 35
Parameter Description Type Size Default
sms-custom-
server
Custom SMS server to send SMS messages to. string Maximum
length: 35
sms-phone Phone number on which the administrator receives
SMS messages.
string Maximum
length: 15
sms-server Send SMS messages using the FortiGuard SMS
server or a custom server.
option - fortiguard
Option Description
fortiguard Send SMS by FortiGuard.
custom Send SMS by custom server.
ssh-certificate Select the certificate to be used by the FortiGate for
authentication with an SSH client.
string Maximum
length: 35
ssh-public-key1 Public key of an SSH client. The client is
authenticated without being asked for credentials.
Create the public-private key pair in the SSH client
application.
user Not
Specified
ssh-public-key2 Public key of an SSH client. The client is
authenticated without being asked for credentials.
Create the public-private key pair in the SSH client
application.
user Not
Specified
ssh-public-key3 Public key of an SSH client. The client is
authenticated without being asked for credentials.
Create the public-private key pair in the SSH client
application.
user Not
Specified
trusthost1 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost10 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost2 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost3 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
Parameter Description Type Size Default
trusthost4 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost5 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost6 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost7 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost8 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
trusthost9 Any IPv4 address or subnet address and netmask
from which the administrator can connect to the
FortiGate unit. Default allows access from any IPv4
address.
ipv4-
classnet
Not
Specified
0.0.0.0
0.0.0.0
two-factor Enable/disable two-factor authentication. option - disable
Option Description
disable Disable two-factor authentication.
fortitoken Use FortiToken or FortiToken mobile two-factor authentication.
fortitoken-cloud FortiToken Cloud Service.
email Send a two-factor authentication code to the configured email-to email
address.
sms Send a two-factor authentication code to the configured sms-server and
sms-phone.
two-factor-
authentication
Authentication method by FortiToken Cloud. option -
Parameter Description Type Size Default
Option Description
fortitoken FortiToken authentication.
email Email one time password.
sms SMS one time password.
two-factor-
notification
Notification method for user activation by FortiToken
Cloud.
option -
Option Description
email Email notification for activation code.
sms SMS notification for activation code.
vdom <name> Virtual domain(s) that the administrator can access.
Virtual domain name.
string Maximum
length: 79
vdom-override Enable to use the names of VDOMs provided by the
remote authentication server to control the VDOMs
that this administrator can access.
option - disable
Option Description
enable Enable VDOM override.
disable Disable VDOM override.
wildcard Enable/disable wildcard RADIUS authentication. option - disable
Option Description
enable Enable username wildcard.
disable Disable username wildcard.

### config system affinity-interrupt

This command is available for model(s): FortiGate 100F, FortiGate 101F, FortiGate 120G,
FortiGate 121G, FortiGate 200F, FortiGate 201F, FortiGate 4200F, FortiGate 4201F,
FortiGate 4400F, FortiGate 4401F, FortiGate 80F DSL, FortiGate 90G, FortiGate 91G,
FortiGate-VM for Aliyun, FortiGate-VM for AWS, FortiGate-VM for Azure, FortiGate-VM for
GCP, FortiGate-VM for OPC, FortiGate-VM64, FortiWiFi 80F 2R 3G4G DSL, FortiWiFi 81F 2R
3G4G DSL.
It is not available for: FortiGate 1000D, FortiGate 1000F, FortiGate 1001F, FortiGate 1100E,
FortiGate 1101E, FortiGate 140E-POE, FortiGate 140E, FortiGate 1800F, FortiGate 1801F,
FortiGate 2000E, FortiGate 200E, FortiGate 201E, FortiGate 2200E, FortiGate 2201E,
FortiGate 2500E, FortiGate 2600F, FortiGate 2601F, FortiGate 3000D, FortiGate 3000F,
FortiGate 3001F, FortiGate 300E, FortiGate 301E, FortiGate 3100D, FortiGate 3200D,
FortiGate 3200F, FortiGate 3201F, FortiGate 3300E, FortiGate 3301E, FortiGate 3400E,
FortiGate 3401E, FortiGate 3500F, FortiGate 3501F, FortiGate 3600E, FortiGate 3601E,
FortiGate 3700D, FortiGate 3700F, FortiGate 3701F, FortiGate 3960E, FortiGate 3980E,
FortiGate 400E Bypass, FortiGate 400E, FortiGate 400F, FortiGate 401E, FortiGate 401F,
FortiGate 5001E1, FortiGate 5001E, FortiGate 500E, FortiGate 501E, FortiGate 600E,
FortiGate 600F, FortiGate 601E, FortiGate 601F, FortiGate 60E DSLJ, FortiGate 60E DSL,
FortiGate 60E-POE, FortiGate 60E, FortiGate 61E, FortiGate 800D, FortiGate 80E-POE,
FortiGate 80E, FortiGate 81E-POE, FortiGate 81E, FortiGate 900D, FortiGate 900G,
FortiGate 901G, FortiGate 90E, FortiGate 91E, FortiGateRugged 70F, FortiWiFi 60E DSLJ,
FortiWiFi 60E DSL, FortiWiFi 60E, FortiWiFi 61E.
Configure interrupt affinity.

#### Syntax

config system affinity-interrupt
Description: Configure interrupt affinity.
edit <id>
set affinity-cpumask {string}
set default-affinity-cpumask {string}
set interrupt {string}
next
end

#### Parameters

config system affinity-interrupt
Parameter Description Type Size Default
affinity-
cpumask
Affinity setting (64-bit hexadecimal value in the format
of 0xxxxxxxxxxxxxxxxx).
string Maximum
length: 127
default-
affinity-
cpumask
Default affinity setting (64-bit hexadecimal value in
the format of 0xxxxxxxxxxxxxxxxx). Read-only.
string Maximum
length: 127

---

## config_system_dhcp_server.md

# config system dhcp server

> Source: `config system dhcp server.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
start-ip Start of IP range. ipv6-
address
Not Specified ::
config prefix-range
Parameter Description Type Size Default
end-prefix End of prefix range. ipv6-
address
Not Specified ::
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
prefix-length Prefix length. integer Minimum
value: 1
Maximum
value: 128
0
start-prefix Start of prefix range. ipv6-
address
Not Specified ::

### config system dhcp server

Configure DHCP servers.

#### Syntax

config system dhcp server
Description: Configure DHCP servers.
edit <id>
set auto-configuration [disable|enable]
set auto-managed-status [disable|enable]
set conflicted-ip-timeout {integer}
set ddns-auth [disable|tsig]
set ddns-key {password_aes256}
set ddns-keyname {string}
set ddns-server-ip {ipv4-address}
set ddns-ttl {integer}
set ddns-update [disable|enable]
set ddns-update-override [disable|enable]
set ddns-zone {string}
set default-gateway {ipv4-address}
set dhcp-settings-from-fortiipam [disable|enable]
set dns-server1 {ipv4-address}
set dns-server2 {ipv4-address}
set dns-server3 {ipv4-address}
set dns-server4 {ipv4-address}
set dns-service [local|default|...]
set domain {string}
config exclude-range
Description: Exclude one or more ranges of IP addresses from being assigned to
clients.
edit <id>
set end-ip {ipv4-address}
set lease-time {integer}
set start-ip {ipv4-address}
set uci-match [disable|enable]
set uci-string <uci-string1>, <uci-string2>, ...
set vci-match [disable|enable]
set vci-string <vci-string1>, <vci-string2>, ...
next
end
set filename {string}
set forticlient-on-net-status [disable|enable]
set interface {string}
set ip-mode [range|usrgrp]
config ip-range
Description: DHCP IP range configuration.
edit <id>
set end-ip {ipv4-address}
set lease-time {integer}
set start-ip {ipv4-address}
set uci-match [disable|enable]
set uci-string <uci-string1>, <uci-string2>, ...
set vci-match [disable|enable]
set vci-string <vci-string1>, <vci-string2>, ...
next
end
set ipsec-lease-hold {integer}
set lease-time {integer}
set mac-acl-default-action [assign|block]
set netmask {ipv4-netmask}
set next-server {ipv4-address}
set ntp-server1 {ipv4-address}
set ntp-server2 {ipv4-address}
set ntp-server3 {ipv4-address}
set ntp-service [local|default|...]
config options
Description: DHCP options.
edit <id>
set code {integer}
set ip {user}
set type [hex|string|...]
set uci-match [disable|enable]
set uci-string <uci-string1>, <uci-string2>, ...
set value {string}
set vci-match [disable|enable]
set vci-string <vci-string1>, <vci-string2>, ...
next
end
set relay-agent {ipv4-address}
config reserved-address
Description: Options for the DHCP server to assign IP settings to specific MAC
addresses.
edit <id>
set action [assign|block|...]
set circuit-id {string}
set circuit-id-type [hex|string]
set description {var-string}
set ip {ipv4-address}
set mac {mac-address}
set remote-id {string}
set remote-id-type [hex|string]
set type [mac|option82]
next
end
set server-type [regular|ipsec]
set shared-subnet [disable|enable]
set status [disable|enable]
set tftp-server <tftp-server1>, <tftp-server2>, ...
set timezone {string}
set timezone-option [disable|default|...]
set vci-match [disable|enable]
set vci-string <vci-string1>, <vci-string2>, ...
set wifi-ac-service [specify|local]
set wifi-ac1 {ipv4-address}
set wifi-ac2 {ipv4-address}
set wifi-ac3 {ipv4-address}
set wins-server1 {ipv4-address}
set wins-server2 {ipv4-address}
next
end

#### Parameters

config system dhcp server
Parameter Description Type Size Default
auto-
configuration
Enable/disable auto configuration. option - enable
Option Description
disable Disable auto configuration.
enable Enable auto configuration.
auto-managed-
status
Enable/disable use of this DHCP server once this
interface has been assigned an IP address from
FortiIPAM.
option - enable
Parameter Description Type Size Default
Option Description
disable Disable use of this DHCP server once this interface has been assigned an IP
address from FortiIPAM.
enable Enable use of this DHCP server once this interface has been assigned an IP
address from FortiIPAM.
conflicted-ip-
timeout
Time in seconds to wait after a conflicted IP
address is removed from the DHCP range before it
can be reused.
integer Minimum
value: 60
Maximum
value:
8640000
1800
ddns-auth DDNS authentication mode. option - disable
Option Description
disable Disable DDNS authentication.
tsig TSIG based on RFC2845.
ddns-key DDNS update key (base 64 encoding). password_
aes256
Not Specified
ddns-keyname DDNS update key name. string Maximum
length: 64
ddns-server-ip DDNS server IP. ipv4-address Not Specified 0.0.0.0
ddns-ttl TTL. integer Minimum
value: 60
Maximum
value: 86400
300
ddns-update Enable/disable DDNS update for DHCP. option - disable
Option Description
disable Disable DDNS update for DHCP.
enable Enable DDNS update for DHCP.
ddns-update-
override
Enable/disable DDNS update override for DHCP. option - disable
Option Description
disable Disable DDNS update override for DHCP.
enable Enable DDNS update override for DHCP.
Parameter Description Type Size Default
ddns-zone Zone of your domain name (ex. DDNS.com). string Maximum
length: 64
default-
gateway
Default gateway IP address assigned by the DHCP
server.
ipv4-address Not Specified 0.0.0.0
dhcp-settings-
from-fortiipam
Enable/disable populating of DHCP server settings
from FortiIPAM.
option - disable
Option Description
disable Disable populating of DHCP server settings from FortiIPAM.
enable Enable populating of DHCP server settings from FortiIPAM.
dns-server1 DNS server 1. ipv4-address Not Specified 0.0.0.0
dns-server2 DNS server 2. ipv4-address Not Specified 0.0.0.0
dns-server3 DNS server 3. ipv4-address Not Specified 0.0.0.0
dns-server4 DNS server 4. ipv4-address Not Specified 0.0.0.0
dns-service Options for assigning DNS servers to DHCP
clients.
option - specify
Option Description
local IP address of the interface the DHCP server is added to becomes the client's
DNS server IP address.
default Clients are assigned the FortiGate's configured DNS servers.
specify Specify up to 3 DNS servers in the DHCP server configuration.
domain Domain name suffix for the IP addresses that the
DHCP server assigns to clients.
string Maximum
length: 35
filename Name of the boot file on the TFTP server. string Maximum
length: 127
forticlient-on-
net-status
Enable/disable FortiClient-On-Net service for this
DHCP server.
option - enable
Option Description
disable Disable FortiClient On-Net Status.
enable Enable FortiClient On-Net Status.
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
Parameter Description Type Size Default
interface DHCP server can assign IP configurations to
clients connected to this interface.
string Maximum
length: 15
ip-mode Method used to assign client IP. option - range
Option Description
range Use range defined by start-ip/end-ip to assign client IP.
usrgrp Use user-group defined method to assign client IP.
ipsec-lease-
hold
DHCP over IPsec leases expire this many seconds
after tunnel down (0 to disable forced-expiry).
integer Minimum
value: 0
Maximum
value:
8640000
60
lease-time Lease time in seconds, 0 means unlimited. integer Minimum
value: 300
Maximum
value:
8640000
604800
mac-acl-
default-action
MAC access control default action (allow or block
assigning IP settings).
option - assign
Option Description
assign Allow the DHCP server to assign IP settings to clients on the MAC access
control list.
block Block the DHCP server from assigning IP settings to clients on the MAC
access control list.
netmask Netmask assigned by the DHCP server. ipv4-netmask Not Specified 0.0.0.0
next-server IP address of a server (for example, a TFTP sever)
that DHCP clients can download a boot file from.
ipv4-address Not Specified 0.0.0.0
ntp-server1 NTP server 1. ipv4-address Not Specified 0.0.0.0
ntp-server2 NTP server 2. ipv4-address Not Specified 0.0.0.0
ntp-server3 NTP server 3. ipv4-address Not Specified 0.0.0.0
ntp-service Options for assigning Network Time Protocol
(NTP) servers to DHCP clients.
option - specify
Option Description
local IP address of the interface the DHCP server is added to becomes the client's
NTP server IP address.
Parameter Description Type Size Default
Option Description
default Clients are assigned the FortiGate's configured NTP servers.
specify Specify up to 3 NTP servers in the DHCP server configuration.
relay-agent Relay agent IP. ipv4-address Not Specified 0.0.0.0
server-type DHCP server can be a normal DHCP server or an
IPsec DHCP server.
option - regular
Option Description
regular Regular DHCP service.
ipsec DHCP over IPsec service.
shared-subnet Enable/disable shared subnet. option - disable
Option Description
disable Disable shared subnet.
enable Enable shared subnet.
status Enable/disable this DHCP configuration. option - enable
Option Description
disable Do not use this DHCP server configuration.
enable Use this DHCP server configuration.
tftp-server
<tftp-
server>
One or more hostnames or IP addresses of the
TFTP servers in quotes separated by spaces.
TFTP server.
string Maximum
length: 63
timezone Select the time zone to be assigned to DHCP
clients.
string Maximum
length: 63
timezone-
option
Options for the DHCP server to set the client's time
zone.
option - disable
Option Description
disable Do not set the client's time zone.
default Clients are assigned the FortiGate's configured time zone.
specify Specify the time zone to be assigned to DHCP clients.
Parameter Description Type Size Default
vci-match Enable/disable vendor class identifier (VCI)
matching. When enabled only DHCP requests with
a matching VCI are served.
option - disable
Option Description
disable Disable VCI matching.
enable Enable VCI matching.
vci-string
<vci-
string>
One or more VCI strings in quotes separated by
spaces.
VCI strings.
string Maximum
length: 255
wifi-ac-service Options for assigning WiFi access controllers to
DHCP clients.
option - specify
Option Description
specify Specify up to 3 WiFi Access Controllers in the DHCP server configuration.
local IP address of the interface the DHCP server is added to becomes the client's
WiFi Access Controller IP address.
wifi-ac1 WiFi Access Controller 1 IP address (DHCP option
138, RFC 5417).
ipv4-address Not Specified 0.0.0.0
wifi-ac2 WiFi Access Controller 2 IP address (DHCP option
138, RFC 5417).
ipv4-address Not Specified 0.0.0.0
wifi-ac3 WiFi Access Controller 3 IP address (DHCP option
138, RFC 5417).
ipv4-address Not Specified 0.0.0.0
wins-server1 WINS server 1. ipv4-address Not Specified 0.0.0.0
wins-server2 WINS server 2. ipv4-address Not Specified 0.0.0.0
config exclude-range
Parameter Description Type Size Default
end-ip End of IP range. ipv4-
address
Not Specified 0.0.0.0
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
Parameter Description Type Size Default
lease-time Lease time in seconds, 0 means default lease time. integer Minimum
value: 300
Maximum
value:
8640000
0
start-ip Start of IP range. ipv4-
address
Not Specified 0.0.0.0
uci-match Enable/disable user class identifier (UCI) matching.
When enabled only DHCP requests with a matching
UCI are served with this range.
option - disable
Option Description
disable Disable UCI matching.
enable Enable UCI matching.
uci-string
<uci-
string>
One or more UCI strings in quotes separated by
spaces.
UCI strings.
string Maximum
length: 255
vci-match Enable/disable vendor class identifier (VCI)
matching. When enabled only DHCP requests with a
matching VCI are served with this range.
option - disable
Option Description
disable Disable VCI matching.
enable Enable VCI matching.
vci-string
<vci-
string>
One or more VCI strings in quotes separated by
spaces.
VCI strings.
string Maximum
length: 255
config ip-range
Parameter Description Type Size Default
end-ip End of IP range. ipv4-
address
Not Specified 0.0.0.0
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
Parameter Description Type Size Default
lease-time Lease time in seconds, 0 means default lease time. integer Minimum
value: 300
Maximum
value:
8640000
0
start-ip Start of IP range. ipv4-
address
Not Specified 0.0.0.0
uci-match Enable/disable user class identifier (UCI) matching.
When enabled only DHCP requests with a matching
UCI are served with this range.
option - disable
Option Description
disable Disable UCI matching.
enable Enable UCI matching.
uci-string
<uci-
string>
One or more UCI strings in quotes separated by
spaces.
UCI strings.
string Maximum
length: 255
vci-match Enable/disable vendor class identifier (VCI)
matching. When enabled only DHCP requests with a
matching VCI are served with this range.
option - disable
Option Description
disable Disable VCI matching.
enable Enable VCI matching.
vci-string
<vci-
string>
One or more VCI strings in quotes separated by
spaces.
VCI strings.
string Maximum
length: 255
config options
Parameter Description Type Size Default
code DHCP option code. integer Minimum
value: 0
Maximum
value: 255
0
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
Parameter Description Type Size Default
ip DHCP option IPs. user Not Specified
type DHCP option type. option - hex
Option Description
hex DHCP option in hex.
string DHCP option in string.
ip DHCP option in IP.
fqdn DHCP option in domain search option format.
uci-match Enable/disable user class identifier (UCI) matching.
When enabled only DHCP requests with a matching
UCI are served with this option.
option - disable
Option Description
disable Disable UCI matching.
enable Enable UCI matching.
uci-string
<uci-
string>
One or more UCI strings in quotes separated by
spaces.
UCI strings.
string Maximum
length: 255
value DHCP option value. string Maximum
length: 312
vci-match Enable/disable vendor class identifier (VCI)
matching. When enabled only DHCP requests with a
matching VCI are served with this option.
option - disable
Option Description
disable Disable VCI matching.
enable Enable VCI matching.
vci-string
<vci-
string>
One or more VCI strings in quotes separated by
spaces.
VCI strings.
string Maximum
length: 255
config reserved-address
Parameter Description Type Size Default
action Options for the DHCP server to configure
the client with the reserved MAC address.
option - reserved
Parameter Description Type Size Default
Option Description
assign Configure the client with this MAC address like any other client.
block Block the DHCP server from assigning IP settings to the client with this MAC
address.
reserved Assign the reserved IP address to the client with this MAC address.
circuit-id Option 82 circuit-ID of the client that will get
the reserved IP address.
string Maximum
length: 312
circuit-id-type DHCP option type. option - string
Option Description
hex DHCP option in hex.
string DHCP option in string.
description Description. var-string Maximum
length: 255
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
ip IP address to be reserved for the MAC
address.
ipv4-
address
Not Specified 0.0.0.0
mac MAC address of the client that will get the
reserved IP address.
mac-
address
Not Specified 00:00:00:00:00:00
remote-id Option 82 remote-ID of the client that will get
the reserved IP address.
string Maximum
length: 312
remote-id-
type
DHCP option type. option - string
Option Description
hex DHCP option in hex.
string DHCP option in string.
type DHCP reserved-address type. option - mac
Option Description
mac Match with MAC address.
option82 Match with DHCP option 82.

---

## config_system_sdwan.md

# config system sdwan

> Source: `config system sdwan.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

### config system sdn-proxy

Configure SDN proxy.

#### Syntax

config system sdn-proxy
Description: Configure SDN proxy.
edit <name>
set password {password_aes256}
set server {string}
set server-port {integer}
set type [general|fortimanager]
set username {string}
next
end

#### Parameters

config system sdn-proxy
Parameter Description Type Size Default
name SDN proxy name. string Maximum
length: 35
password SDN proxy password. password_
aes256
Not
Specified
server Server address of the SDN proxy. string Maximum
length: 127
server-port Port number of the SDN proxy. integer Minimum
value: 0
Maximum
value:
65535
0
type Type of SDN proxy. option - general
Option Description
general General HTTP proxy.
fortimanager FortiManager SDN proxy.
username SDN proxy username. string Maximum
length: 64

### config system sdwan

Configure redundant Internet connections with multiple outbound links and health-check profiles.

#### Syntax

config system sdwan
Description: Configure redundant Internet connections with multiple outbound links and
health-check profiles.
set app-perf-log-period {integer}
config duplication
Description: Create SD-WAN duplication rule.
edit <id>
set dstaddr <name1>, <name2>, ...
set dstaddr6 <name1>, <name2>, ...
set dstintf <name1>, <name2>, ...
set packet-de-duplication [enable|disable]
set packet-duplication [disable|force|...]
set service <name1>, <name2>, ...
set service-id <id1>, <id2>, ...
set sla-match-service [enable|disable]
set srcaddr <name1>, <name2>, ...
set srcaddr6 <name1>, <name2>, ...
set srcintf <name1>, <name2>, ...
next
end
set duplication-max-num {integer}
set fail-alert-interfaces <name1>, <name2>, ...
set fail-detect [enable|disable]
config health-check
Description: SD-WAN status checking or health checking. Identify a server on the
Internet and determine how SD-WAN verifies that the FortiGate can communicate with it.
edit <name>
set addr-mode [ipv4|ipv6]
set class-id {integer}
set detect-mode [active|passive|...]
set diffservcode {user}
set dns-match-ip {ipv4-address}
set dns-request-domain {string}
set embed-measured-health [enable|disable]
set failtime {integer}
set ftp-file {string}
set ftp-mode [passive|port]
set ha-priority {integer}
set http-agent {string}
set http-get {string}
set http-match {string}
set interval {integer}
set members <seq-num1>, <seq-num2>, ...
set mos-codec [g711|g722|...]
set packet-size {integer}
set password {password}
set port {integer}
set probe-count {integer}
set probe-packets [disable|enable]
set probe-timeout {integer}
set protocol [ping|tcp-echo|...]
set quality-measured-method [half-open|half-close]
set recoverytime {integer}
set security-mode [none|authentication]
set server {string}
config sla
Description: Service level agreement (SLA).
edit <id>
set jitter-threshold {integer}
set latency-threshold {integer}
set link-cost-factor {option1}, {option2}, ...
set mos-threshold {string}
set packetloss-threshold {integer}
set priority-in-sla {integer}
set priority-out-sla {integer}
next
end
set sla-fail-log-period {integer}
set sla-id-redistribute {integer}
set sla-pass-log-period {integer}
set source {ipv4-address}
set source6 {ipv6-address}
set system-dns [disable|enable]
set threshold-alert-jitter {integer}
set threshold-alert-latency {integer}
set threshold-alert-packetloss {integer}
set threshold-warning-jitter {integer}
set threshold-warning-latency {integer}
set threshold-warning-packetloss {integer}
set update-cascade-interface [enable|disable]
set update-static-route [enable|disable]
set user {string}
set vrf {integer}
next
end
set load-balance-mode [source-ip-based|weight-based|...]
config members
Description: FortiGate interfaces added to the SD-WAN.
edit <seq-num>
set comment {var-string}
set cost {integer}
set gateway {ipv4-address}
set gateway6 {ipv6-address}
set ingress-spillover-threshold {integer}
set interface {string}
set preferred-source {ipv4-address}
set priority {integer}
set priority6 {integer}
set source {ipv4-address}
set source6 {ipv6-address}
set spillover-threshold {integer}
set status [disable|enable]
set transport-group {integer}
set volume-ratio {integer}
set weight {integer}
set zone {string}
next
end
config neighbor
Description: Create SD-WAN neighbor from BGP neighbor table to control route
advertisements according to SLA status.
edit <ip>
set health-check {string}
set member <seq-num1>, <seq-num2>, ...
set minimum-sla-meet-members {integer}
set mode [sla|speedtest]
set role [standalone|primary|...]
set service-id {integer}
set sla-id {integer}
next
end
set neighbor-hold-boot-time {integer}
set neighbor-hold-down [enable|disable]
set neighbor-hold-down-time {integer}
config service
Description: Create SD-WAN rules (also called services) to control how sessions are
distributed to interfaces in the SD-WAN.
edit <id>
set addr-mode [ipv4|ipv6]
set agent-exclusive [enable|disable]
set bandwidth-weight {integer}
set default [enable|disable]
set dscp-forward [enable|disable]
set dscp-forward-tag {user}
set dscp-reverse [enable|disable]
set dscp-reverse-tag {user}
set dst <name1>, <name2>, ...
set dst-negate [enable|disable]
set dst6 <name1>, <name2>, ...
set end-port {integer}
set end-src-port {integer}
set gateway [enable|disable]
set groups <name1>, <name2>, ...
set hash-mode [round-robin|source-ip-based|...]
set health-check <name1>, <name2>, ...
set hold-down-time {integer}
set input-device <name1>, <name2>, ...
set input-device-negate [enable|disable]
set input-zone <name1>, <name2>, ...
set internet-service [enable|disable]
set internet-service-app-ctrl <id1>, <id2>, ...
set internet-service-app-ctrl-category <id1>, <id2>, ...
set internet-service-app-ctrl-group <name1>, <name2>, ...
set internet-service-custom <name1>, <name2>, ...
set internet-service-custom-group <name1>, <name2>, ...
set internet-service-group <name1>, <name2>, ...
set internet-service-name <name1>, <name2>, ...
set jitter-weight {integer}
set latency-weight {integer}
set link-cost-factor [latency|jitter|...]
set link-cost-threshold {integer}
set load-balance [enable|disable]
set minimum-sla-meet-members {integer}
set mode [auto|manual|...]
set name {string}
set packet-loss-weight {integer}
set passive-measurement [enable|disable]
set priority-members <seq-num1>, <seq-num2>, ...
set priority-zone <name1>, <name2>, ...
set protocol {integer}
set quality-link {integer}
set role [standalone|primary|...]
set shortcut [enable|disable]
set shortcut-priority [enable|disable|...]
config sla
Description: Service level agreement (SLA).
edit <health-check>
set id {integer}
next
end
set sla-compare-method [order|number]
set sla-stickiness [enable|disable]
set src <name1>, <name2>, ...
set src-negate [enable|disable]
set src6 <name1>, <name2>, ...
set standalone-action [enable|disable]
set start-port {integer}
set start-src-port {integer}
set status [enable|disable]
set tie-break [zone|cfg-order|...]
set tos {user}
set tos-mask {user}
set use-shortcut-sla [enable|disable]
set users <name1>, <name2>, ...
set zone-mode [enable|disable]
next
end
set speedtest-bypass-routing [disable|enable]
set status [disable|enable]
config zone
Description: Configure SD-WAN zones.
edit <name>
set advpn-health-check {string}
set advpn-select [enable|disable]
set minimum-sla-meet-members {integer}
set service-sla-tie-break [cfg-order|fib-best-match|...]
next
end
end

#### Parameters

config system sdwan
Parameter Description Type Size Default
app-perf-log-
period
Time interval in seconds that application performance
logs are generated.
integer Minimum
value: 0
Maximum
value: 3600
0
duplication-
max-num
Maximum number of interface members a packet is
duplicated in the SD-WAN zone.
integer Minimum
value: 2
Maximum
value: 4
2
fail-alert-
interfaces
<name>
Physical interfaces that will be alerted.
Physical interface name.
string Maximum
length: 79
fail-detect Enable/disable SD-WAN Internet connection status
checking (failure detection).
option - disable
Parameter Description Type Size Default
Option Description
enable Enable status checking.
disable Disable status checking.
load-balance-
mode
Algorithm or mode to use for load balancing Internet
traffic to SD-WAN members.
option - source-ip-
based
Option Description
source-ip-based Source IP load balancing. All traffic from a source IP is sent to the same
interface.
weight-based Weight-based load balancing. Interfaces with higher weights have higher
priority and get more traffic.
usage-based Usage-based load balancing. All traffic is sent to the first interface on the list.
When the bandwidth on that interface exceeds the spill-over limit new traffic is
sent to the next interface.
source-dest-ip-
based
Source and destination IP load balancing. All traffic from a source IP to a
destination IP is sent to the same interface.
measured-
volume-based
Volume-based load balancing. Traffic is load balanced based on traffic volume
(in bytes). More traffic is sent to interfaces with higher volume ratios.
neighbor-
hold-boot-
time
Waiting period in seconds when switching from the
primary neighbor to the secondary neighbor from the
neighbor start.
integer Minimum
value: 0
Maximum
value:
10000000
0
neighbor-
hold-down
Enable/disable hold switching from the secondary
neighbor to the primary neighbor.
option - disable
Option Description
enable Enable hold switching from the secondary neighbor to the primary neighbor.
disable Disable hold switching from the secondary neighbor to the primary neighbor.
neighbor-
hold-down-
time
Waiting period in seconds when switching from the
secondary neighbor to the primary neighbor when hold-
down is disabled.
integer Minimum
value: 0
Maximum
value:
10000000
0
speedtest-
bypass-
routing
Enable/disable bypass routing when speedtest on a
SD-WAN member.
option - disable
Parameter Description Type Size Default
Option Description
disable Disable SD-WAN.
enable Enable SD-WAN.
status Enable/disable SD-WAN. option - disable
Option Description
disable Disable SD-WAN.
enable Enable SD-WAN.
config duplication
Parameter Description Type Size Default
dstaddr
<name>
Destination address or address group names.
Address or address group name.
string Maximum
length: 79
dstaddr6
<name>
Destination address6 or address6 group names.
Address6 or address6 group name.
string Maximum
length: 79
dstintf
<name>
Outgoing (egress) interfaces or zones.
Interface, zone or SDWAN zone name.
string Maximum
length: 79
id Duplication rule ID. integer Minimum
value: 1
Maximum
value: 255
0
packet-de-
duplication
Enable/disable discarding of packets that have been
duplicated.
option - disable
Option Description
enable Enable discarding of packets that have been duplicated.
disable Disable discarding of packets that have been duplicated.
packet-
duplication
Configure packet duplication method. option - disable
Option Description
disable Disable packet duplication.
force Duplicate packets across all interface members of the SD-WAN zone.
on-demand Duplicate packets across all interface members of the SD-WAN zone based
on the link quality.
Parameter Description Type Size Default
service
<name>
Service and service group name.
Service and service group name.
string Maximum
length: 79
service-id
<id>
SD-WAN service rule ID list.
SD-WAN service rule ID.
integer Minimum
value: 0
Maximum
value:
4294967295
sla-match-
service
Enable/disable packet duplication matching health-
check SLAs in service rule.
option - disable
Option Description
enable Enable packet duplication matching health-check SLAs in service rule
(matching all SLAs of current defined service).
disable Disable packet duplication matching health-check SLAs in service rule
(matching all SLAs of all defined health-check).
srcaddr
<name>
Source address or address group names.
Address or address group name.
string Maximum
length: 79
srcaddr6
<name>
Source address6 or address6 group names.
Address6 or address6 group name.
string Maximum
length: 79
srcintf
<name>
Incoming (ingress) interfaces or zones.
Interface, zone or SDWAN zone name.
string Maximum
length: 79
config health-check
Parameter Description Type Size Default
addr-mode Address mode (IPv4 or IPv6). option - ipv4
Option Description
ipv4 IPv4 mode.
ipv6 IPv6 mode.
class-id Traffic class ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
detect-mode The mode determining how to detect the
server.
option - active
Parameter Description Type Size Default
Option Description
active The probes are sent actively.
passive The traffic measures health without probes.
prefer-passive The probes are sent in case of no new traffic.
remote Link health obtained from remote peers.
agent-based Traffic health is measured from the fabric connectors.
diffservcode Differentiated services code point (DSCP)
in the IP header of the probe packet.
user Not Specified
dns-match-ip Response IP expected from DNS server if
the protocol is DNS.
ipv4-
address
Not Specified 0.0.0.0
dns-request-
domain
Fully qualified domain name to resolve for
the DNS probe.
string Maximum
length: 255
www.example.com
embed-
measured-
health
Enable/disable embedding measured
health information.
option - disable
Option Description
enable Enable embed measured health.
disable Disable embed measured health.
failtime Number of failures before server is
considered lost.
integer Minimum
value: 1
Maximum
value: 3600
5
ftp-file Full path and file name on the FTP server
to download for FTP health-check to
probe.
string Maximum
length: 254
ftp-mode FTP mode. option - passive
Option Description
passive The FTP health-check initiates and establishes the data connection.
port The FTP server initiates and establishes the data connection.
ha-priority HA election priority. integer Minimum
value: 1
Maximum
value: 50
1
Parameter Description Type Size Default
http-agent String in the http-agent field in the HTTP
header.
string Maximum
length: 1024
Chrome/ Safari/
http-get URL used to communicate with the server
if the protocol if the protocol is HTTP.
string Maximum
length: 1024
/
http-match Response string expected from the server
if the protocol is HTTP.
string Maximum
length: 1024
interval Status check interval in milliseconds, or
the time between attempting to connect to
the server.
integer Minimum
value: 20
Maximum
value:
3600000
500
members
<seq-num>
Member sequence number list.
Member sequence number.
integer Minimum
value: 0
Maximum
value:
4294967295
mos-codec Codec to use for MOS calculation. option - g711
Option Description
g711 Calculate MOS based on the G.711 codec.
g722 Calculate MOS based on the G.722 codec.
g729 Calculate MOS based on the G.729 codec.
name Status check or health check name. string Maximum
length: 35
packet-size Packet size of a TWAMP test session. integer Minimum
value: 0
Maximum
value: 65535
124
password TWAMP controller password in
authentication mode.
password Not Specified
port Port number used to communicate with
the server over the selected protocol.
integer Minimum
value: 0
Maximum
value: 65535
0
probe-count Number of most recent probes that should
be used to calculate latency and jitter.
integer Minimum
value: 5
Maximum
value: 30
30
Parameter Description Type Size Default
probe-packets Enable/disable transmission of probe
packets.
option - enable
Option Description
disable Disable transmission of probe packets.
enable Enable transmission of probe packets.
probe-timeout Time to wait before a probe packet is
considered lost.
integer Minimum
value: 20
Maximum
value:
3600000
500
protocol Protocol used to determine if the
FortiGate can communicate with the
server.
option - ping
Option Description
ping Use PING to test the link with the server.
tcp-echo Use TCP echo to test the link with the server.
udp-echo Use UDP echo to test the link with the server.
http Use HTTP-GET to test the link with the server.
https Use HTTPS-GET to test the link with the server.
twamp Use TWAMP to test the link with the server.
dns Use DNS query to test the link with the server.
tcp-connect Use a full TCP connection to test the link with the server.
ftp Use FTP to test the link with the server.
quality-
measured-
method
Method to measure the quality of tcp-
connect.
option - half-open
Option Description
half-open Measure the round trip between syn and ack.
half-close Measure the round trip between fin and ack.
recoverytime Number of successful responses received
before server is considered recovered.
integer Minimum
value: 1
Maximum
value: 3600
5
security-mode Twamp controller security mode. option - none
Parameter Description Type Size Default
Option Description
none Unauthenticated mode.
authentication Authenticated mode.
server IP address or FQDN name of the server. string Maximum
length: 79
sla-fail-log-
period
Time interval in seconds that SLA fail log
messages will be generated.
integer Minimum
value: 0
Maximum
value: 3600
0
sla-id-
redistribute
Select the ID from the SLA sub-table. The
selected SLA's priority value will be
distributed into the routing table.
integer Minimum
value: 0
Maximum
value: 32
0
sla-pass-log-
period
Time interval in seconds that SLA pass
log messages will be generated.
integer Minimum
value: 0
Maximum
value: 3600
0
source Source IP address used in the health-
check packet to the server.
ipv4-
address
Not Specified 0.0.0.0
source6 Source IPv6 address used in the health-
check packet to server.
ipv6-
address
Not Specified ::
system-dns Enable/disable system DNS as the probe
server.
option - disable
Option Description
disable Disable system DNS as the probe server.
enable Enable system DNS as the probe server.
threshold-alert-
jitter
Alert threshold for jitter. integer Minimum
value: 0
Maximum
value:
4294967295
0
threshold-alert-
latency
Alert threshold for latency. integer Minimum
value: 0
Maximum
value:
4294967295
0
Parameter Description Type Size Default
threshold-alert-
packetloss
Alert threshold for packet loss. integer Minimum
value: 0
Maximum
value: 100
0
threshold-
warning-jitter
Warning threshold for jitter. integer Minimum
value: 0
Maximum
value:
4294967295
0
threshold-
warning-
latency
Warning threshold for latency. integer Minimum
value: 0
Maximum
value:
4294967295
0
threshold-
warning-
packetloss
Warning threshold for packet loss. integer Minimum
value: 0
Maximum
value: 100
0
update-
cascade-
interface
Enable/disable update cascade interface. option - enable
Option Description
enable Enable update cascade interface.
disable Disable update cascade interface.
update-static-
route
Enable/disable updating the static route. option - enable
Option Description
enable Enable updating the static route.
disable Disable updating the static route.
user The user name to access probe server. string Maximum
length: 64
vrf Virtual Routing Forwarding ID. integer Minimum
value: 0
Maximum
value: 251
0
config sla
Parameter Description Type Size Default
health-check SD-WAN health-check. string Maximum
length: 35
id SLA ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
config members
Parameter Description Type Size Default
comment Comments. var-string Maximum
length: 255
cost Cost of this interface for services in SLA mode. integer Minimum
value: 0
Maximum
value:
4294967295
0
gateway The default gateway for this interface. Usually the
default gateway of the Internet service provider that
this interface is connected to.
ipv4-
address
Not Specified 0.0.0.0
gateway6 IPv6 gateway. ipv6-
address
Not Specified ::
ingress-
spillover-
threshold
Ingress spillover threshold for this interface. When
this traffic volume threshold is reached, new sessions
spill over to other interfaces in the SD-WAN.
integer Minimum
value: 0
Maximum
value:
16776000
0
interface Interface name. string Maximum
length: 15
preferred-
source
Preferred source of route for this member. ipv4-
address
Not Specified 0.0.0.0
priority Priority of the interface for IPv4. Used for SD-WAN
rules or priority rules.
integer Minimum
value: 1
Maximum
value: 65535
1
Parameter Description Type Size Default
priority6 Priority of the interface for IPv6. Used for SD-WAN
rules or priority rules.
integer Minimum
value: 1
Maximum
value: 65535
1024
seq-num Sequence number. integer Minimum
value: 0
Maximum
value: 512
0
source Source IP address used in the health-check packet to
the server.
ipv4-
address
Not Specified 0.0.0.0
source6 Source IPv6 address used in the health-check packet
to the server.
ipv6-
address
Not Specified ::
spillover-
threshold
Egress spillover threshold for this interface. When
this traffic volume threshold is reached, new sessions
spill over to other interfaces in the SD-WAN.
integer Minimum
value: 0
Maximum
value:
16776000
0
status Enable/disable this interface in the SD-WAN. option - enable
Option Description
disable Disable this interface in the SD-WAN.
enable Enable this interface in the SD-WAN.
transport-
group
Measured transport group. integer Minimum
value: 0
Maximum
value: 255
0
volume-ratio Measured volume ratio. integer Minimum
value: 1
Maximum
value: 255
1
weight Weight of this interface for weighted load balancing.
More traffic is directed to interfaces with higher
weights.
integer Minimum
value: 1
Maximum
value: 255
1
zone Zone name. string Maximum
length: 35
virtual-wan-
link
config neighbor
Parameter Description Type Size Default
health-check SD-WAN health-check name. string Maximum
length: 35
ip IP/IPv6 address of neighbor or neighbor-group
name.
string Maximum
length: 45
member
<seq-num>
Member sequence number list.
Member sequence number.
integer Minimum
value: 0
Maximum
value:
4294967295
minimum-sla-
meet-
members
Minimum number of members which meet SLA
when the neighbor is preferred.
integer Minimum
value: 1
Maximum
value: 255
1
mode What metric to select the neighbor. option - sla
Option Description
sla Select neighbor based on SLA link quality.
speedtest Select neighbor based on the speedtest status.
role Role of neighbor. option - standalone
Option Description
standalone Standalone neighbor.
primary Primary neighbor.
secondary Secondary neighbor.
service-id SD-WAN service ID to work with the neighbor. integer Minimum
value: 0
Maximum
value:
4294967295
0
sla-id SLA ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
config service
Parameter Description Type Size Default
addr-mode Address mode (IPv4 or IPv6). option - ipv4
Option Description
ipv4 IPv4 mode.
ipv6 IPv6 mode.
agent-exclusive Set/unset the service as agent use exclusively. option - disable
Option Description
enable Set the service as agent use exclusively.
disable Unset the service as agent use exclusively.
bandwidth-
weight
Coefficient of reciprocal of available bidirectional
bandwidth in the formula of custom-profile-1.
integer Minimum
value: 0
Maximum
value:
10000000
0
default Enable/disable use of SD-WAN as default service. option - disable
Option Description
enable Enable use of SD-WAN as default service.
disable Disable use of SD-WAN as default service.
dscp-forward Enable/disable forward traffic DSCP tag. option - disable
Option Description
enable Enable use of forward DSCP tag.
disable Disable use of forward DSCP tag.
dscp-forward-
tag
Forward traffic DSCP tag. user Not Specified
dscp-reverse Enable/disable reverse traffic DSCP tag. option - disable
Option Description
enable Enable use of reverse DSCP tag.
disable Disable use of reverse DSCP tag.
dscp-reverse-
tag
Reverse traffic DSCP tag. user Not Specified
Parameter Description Type Size Default
dst <name> Destination address name.
Address or address group name.
string Maximum
length: 79
dst-negate Enable/disable negation of destination address
match.
option - disable
Option Description
enable Enable destination address negation.
disable Disable destination address negation.
dst6 <name> Destination address6 name.
Address6 or address6 group name.
string Maximum
length: 79
end-port End destination port number. integer Minimum
value: 0
Maximum
value: 65535
65535
end-src-port End source port number. integer Minimum
value: 0
Maximum
value: 65535
65535
gateway Enable/disable SD-WAN service gateway. option - disable
Option Description
enable Enable SD-WAN service gateway.
disable Disable SD-WAN service gateway.
groups <name> User groups.
Group name.
string Maximum
length: 79
hash-mode Hash algorithm for selected priority members for
load balance mode.
option - round-robin
Option Description
round-robin All traffic are distributed to selected interfaces in equal portions and circular
order.
source-ip-based All traffic from a source IP is sent to the same interface.
source-dest-ip-
based
All traffic from a source IP to a destination IP is sent to the same interface.
inbandwidth All traffic are distributed to a selected interface with most available
bandwidth for incoming traffic.
Parameter Description Type Size Default
Option Description
outbandwidth All traffic are distributed to a selected interface with most available
bandwidth for outgoing traffic.
bibandwidth All traffic are distributed to a selected interface with most available
bandwidth for both incoming and outgoing traffic.
health-check
<name>
Health check list.
Health check name.
string Maximum
length: 79
hold-down-time Waiting period in seconds when switching from
the back-up member to the primary member.
integer Minimum
value: 0
Maximum
value:
10000000
0
id SD-WAN rule ID. integer Minimum
value: 1
Maximum
value: 4000
0
input-device
<name>
Source interface name.
Interface name.
string Maximum
length: 79
input-device-
negate
Enable/disable negation of input device match. option - disable
Option Description
enable Enable negation of input device match.
disable Disable negation of input device match.
input-zone
<name>
Source input-zone name.
Zone.
string Maximum
length: 79
internet-service Enable/disable use of Internet service for
application-based load balancing.
option - disable
Option Description
enable Enable cloud service to support application-based load balancing.
disable Disable cloud service to support application-based load balancing.
internet-service-
app-ctrl <id>
Application control based Internet Service ID list.
Application control based Internet Service ID.
integer Minimum
value: 0
Maximum
value:
4294967295
Parameter Description Type Size Default
internet-service-
app-ctrl-
category <id>
IDs of one or more application control categories.
Application control category ID.
integer Minimum
value: 0
Maximum
value:
4294967295
internet-service-
app-ctrl-group
<name>
Application control based Internet Service group
list.
Application control based Internet Service group
name.
string Maximum
length: 79
internet-service-
custom <name>
Custom Internet service name list.
Custom Internet service name.
string Maximum
length: 79
internet-service-
custom-group
<name>
Custom Internet Service group list.
Custom Internet Service group name.
string Maximum
length: 79
internet-service-
group <name>
Internet Service group list.
Internet Service group name.
string Maximum
length: 79
internet-service-
name <name>
Internet service name list.
Internet service name.
string Maximum
length: 79
jitter-weight Coefficient of jitter in the formula of custom-profile-
1.
integer Minimum
value: 0
Maximum
value:
10000000
0
latency-weight Coefficient of latency in the formula of custom-
profile-1.
integer Minimum
value: 0
Maximum
value:
10000000
0
link-cost-factor Link cost factor. option - latency
Option Description
latency Select link based on latency.
jitter Select link based on jitter.
packet-loss Select link based on packet loss.
inbandwidth Select link based on available bandwidth of incoming traffic.
outbandwidth Select link based on available bandwidth of outgoing traffic.
bibandwidth Select link based on available bandwidth of bidirectional traffic.
custom-profile-1 Select link based on customized profile.
Parameter Description Type Size Default
link-cost-
threshold
Percentage threshold change of link cost values
that will result in policy route regeneration.
integer Minimum
value: 0
Maximum
value:
10000000
10
load-balance Enable/disable load-balance. option - disable
Option Description
enable Enable load-balance.
disable Disable load-balance.
minimum-sla-
meet-members
Minimum number of members which meet SLA. integer Minimum
value: 0
Maximum
value: 255
0
mode Control how the SD-WAN rule sets the priority of
interfaces in the SD-WAN.
option - manual
Option Description
auto Assign interfaces a priority based on quality.
manual Assign interfaces a priority manually.
priority Assign interfaces a priority based on the link-cost-factor quality of the
interface.
sla Assign interfaces a priority based on selected SLA settings.
name SD-WAN rule name. string Maximum
length: 35
packet-loss-
weight
Coefficient of packet-loss in the formula of
custom-profile-1.
integer Minimum
value: 0
Maximum
value:
10000000
0
passive-
measurement
Enable/disable passive measurement based on
the service criteria.
option - disable
Option Description
enable Enable passive measurement of user traffic.
disable Disable passive measurement of user traffic.
Parameter Description Type Size Default
priority-
members
<seq-num>
Member sequence number list.
Member sequence number.
integer Minimum
value: 0
Maximum
value:
4294967295
priority-zone
<name>
Priority zone name list.
Priority zone name.
string Maximum
length: 79
protocol Protocol number. integer Minimum
value: 0
Maximum
value: 255
0
quality-link Quality grade. integer Minimum
value: 0
Maximum
value: 255
0
role Service role to work with neighbor. option - standalone
Option Description
standalone Standalone service.
primary Primary service for primary neighbor.
secondary Secondary service for secondary neighbor.
shortcut Enable/disable shortcut for this service. option - enable
Option Description
enable Enable use of ADVPN shortcut for this service.
disable Disable use of ADVPN shortcut for this service.
shortcut-priority High priority of ADVPN shortcut for this service. option - auto
Option Description
enable Enable a high priority of ADVPN shortcut for this service.
disable Disable a high priority of ADVPN shortcut for this service.
auto Auto enable a high priority of ADVPN shortcut for this service if ADVPN2.0
enabled.
sla-compare-
method
Method to compare SLA value for SLA mode. option - order
Parameter Description Type Size Default
Option Description
order Compare SLA value based on the order of health-check.
number Compare SLA value based on the number of satisfied health-check. Limits
health-checks to only configured member interfaces.
sla-stickiness Enable/disable SLA stickiness. option - disable
Option Description
enable Traffic remains in the original session path if the path is within the SLA.
disable Traffic switches to the best path regardless of the SLA.
src <name> Source address name.
Address or address group name.
string Maximum
length: 79
src-negate Enable/disable negation of source address match. option - disable
Option Description
enable Enable source address negation.
disable Disable source address negation.
src6 <name> Source address6 name.
Address6 or address6 group name.
string Maximum
length: 79
standalone-
action
Enable/disable service when selected neighbor
role is standalone while service role is not
standalone.
option - disable
Option Description
enable Enable service when selected neighbor role is standalone.
disable Disable service when selected neighbor role is standalone.
start-port Start destination port number. integer Minimum
value: 0
Maximum
value: 65535
1
start-src-port Start source port number. integer Minimum
value: 0
Maximum
value: 65535
1
status Enable/disable SD-WAN service. option - enable
Parameter Description Type Size Default
Option Description
enable Enable SD-WAN service.
disable Disable SD-WAN service.
tie-break Method of selecting member if more than one
meets the SLA.
option - zone
Option Description
zone Use the setting that is configured for the members' zone.
cfg-order Members that meet the SLA are selected in the order they are configured.
fib-best-match Members that meet the SLA are selected that match the longest prefix in the
routing table.
input-device Members that meet the SLA are selected by matching the input device.
tos Type of service bit pattern. user Not Specified
tos-mask Type of service evaluated bits. user Not Specified
use-shortcut-sla Enable/disable use of ADVPN shortcut for quality
comparison.
option - enable
Option Description
enable Enable use of ADVPN shortcut for quality comparison.
disable Disable use of ADVPN shortcut for quality comparison.
users <name> User name.
User name.
string Maximum
length: 79
zone-mode Enable/disable zone mode. option - disable
Option Description
enable Traffic steered based on zone.
disable Traffic steered based on member.
config sla
Parameter Description Type Size Default
health-check SD-WAN health-check. string Maximum
length: 35
Parameter Description Type Size Default
id SLA ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
config zone
Parameter Description Type Size Default
advpn-health-
check
Health check for ADVPN local overlay link quality. string Maximum
length: 35
advpn-select Enable/disable selection of ADVPN based on SDWAN
information.
option - disable
Option Description
enable Enable selection of ADVPN based on SDWAN information.
disable Disable selection of ADVPN based on SDWAN information.
minimum-sla-
meet-
members
Minimum number of members which meet SLA when
the neighbor is preferred.
integer Minimum
value: 1
Maximum
value: 255
1
name Zone name. string Maximum
length: 35
service-sla-
tie-break
Method of selecting member if more than one meets the
SLA.
option - cfg-order
Option Description
cfg-order Members that meet the SLA are selected in the order they are configured.
fib-best-match Members that meet the SLA are selected that match the longest prefix in the
routing table.
input-device Members that meet the SLA are selected by matching the input device.

### config system serial-port

This command is available for model(s): FortiGateRugged 70F.
It is not available for: FortiGate 1000D, FortiGate 1000F, FortiGate 1001F, FortiGate 100F,
FortiGate 101F, FortiGate 1100E, FortiGate 1101E, FortiGate 120G, FortiGate 121G,
FortiGate 140E-POE, FortiGate 140E, FortiGate 1800F, FortiGate 1801F, FortiGate 2000E,
FortiGate 200E, FortiGate 200F, FortiGate 201E, FortiGate 201F, FortiGate 2200E, FortiGate
2201E, FortiGate 2500E, FortiGate 2600F, FortiGate 2601F, FortiGate 3000D, FortiGate
3000F, FortiGate 3001F, FortiGate 300E, FortiGate 301E, FortiGate 3100D, FortiGate 3200D,
FortiGate 3200F, FortiGate 3201F, FortiGate 3300E, FortiGate 3301E, FortiGate 3400E,
FortiGate 3401E, FortiGate 3500F, FortiGate 3501F, FortiGate 3600E, FortiGate 3601E,
FortiGate 3700D, FortiGate 3700F, FortiGate 3701F, FortiGate 3960E, FortiGate 3980E,
FortiGate 400E Bypass, FortiGate 400E, FortiGate 400F, FortiGate 401E, FortiGate 401F,
FortiGate 4200F, FortiGate 4201F, FortiGate 4400F, FortiGate 4401F, FortiGate 5001E1,
FortiGate 5001E, FortiGate 500E, FortiGate 501E, FortiGate 600E, FortiGate 600F, FortiGate
601E, FortiGate 601F, FortiGate 60E DSLJ, FortiGate 60E DSL, FortiGate 60E-POE,
FortiGate 60E, FortiGate 61E, FortiGate 800D, FortiGate 80E-POE, FortiGate 80E, FortiGate
80F DSL, FortiGate 81E-POE, FortiGate 81E, FortiGate 900D, FortiGate 900G, FortiGate
901G, FortiGate 90E, FortiGate 90G, FortiGate 91E, FortiGate 91G, FortiGate-VM for Aliyun,
FortiGate-VM for AWS, FortiGate-VM for Azure, FortiGate-VM for GCP, FortiGate-VM for
OPC, FortiGate-VM64, FortiWiFi 60E DSLJ, FortiWiFi 60E DSL, FortiWiFi 60E, FortiWiFi 61E,
FortiWiFi 80F 2R 3G4G DSL, FortiWiFi 81F 2R 3G4G DSL.
Serial port list. Read-only.

#### Syntax

config system serial-port
Description: Serial port list. Read-only.
edit <name>
next
end

#### Parameters

config system serial-port
Parameter Description Type Size Default
name Serial port name. string Maximum
length: 35

### config system session-helper

Configure session helper.

#### Syntax

config system session-helper
Description: Configure session helper.
edit <id>
set name [ftp|tftp|...]
set port {integer}
set protocol {integer}

---

## config_system_zone.md

# config system zone

> Source: `config system zone.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
power-level Power level. integer Minimum
value: 0
Maximum
value: 17
17
rogue-scan Enable/disable rogue scan. option - disable
Option Description
enable Enable rogue scan.
disable Disable rogue scan.
rogue-scan-
mac-
adjacency
MAC adjacency. integer Minimum
value: 0
Maximum
value: 31
7
short-guard-
interval
Enable/disable short guard interval. option - disable
Option Description
enable 400 ns long guard interval.
disable 800 ns short guard interval.

### config system zone

Configure zones to group two or more interfaces. When a zone is created you can configure policies for the zone instead
of individual interfaces in the zone.

#### Syntax

config system zone
Description: Configure zones to group two or more interfaces. When a zone is created you
can configure policies for the zone instead of individual interfaces in the zone.
edit <name>
set description {string}
set interface <interface-name1>, <interface-name2>, ...
set intrazone [allow|deny]
config tagging
Description: Config object tagging.
edit <name>
set category {string}
set tags <name1>, <name2>, ...
next
end
next
end

#### Parameters

config system zone
Parameter Description Type Size Default
description Description. string Maximum
length: 127
interface
<interface-
name>
Add interfaces to this zone. Interfaces must not be
assigned to another zone or have firewall policies
defined.
Select interfaces to add to the zone.
string Maximum
length: 79
intrazone Allow or deny traffic routing between different
interfaces in the same zone.
option - deny
Option Description
allow Allow traffic between interfaces in the zone.
deny Deny traffic between interfaces in the zone.
name Zone name. string Maximum
length: 35
config tagging
Parameter Description Type Size Default
category Tag category. string Maximum
length: 63
name Tagging entry name. string Maximum
length: 63
tags <name> Tags.
Tag name.
string Maximum
length: 79

---

## config_user_group.md

# config user group

> Source: `config user group.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
source-ip6 IPv6 source for communications to FSSO
agent.
ipv6-
address
Not
Specified
::
ssl Enable/disable use of SSL. option - disable
Option Description
enable Enable use of SSL.
disable Disable use of SSL.
ssl-server-
host-ip-check
Enable/disable server host/IP
verification.
option - disable
Option Description
enable Enable server host/IP verification.
disable Disable server host/IP verification.
ssl-trusted-
cert
Trusted server certificate or CA
certificate.
string Maximum
length: 79
type Server type. option - default
Option Description
default All other unspecified types of servers.
fortinac FortiNAC server.
user-info-
server
LDAP server to get user information. string Maximum
length: 35

### config user group

Configure user groups.

#### Syntax

config user group
Description: Configure user groups.
edit <name>
set auth-concurrent-override [enable|disable]
set auth-concurrent-value {integer}
set authtimeout {integer}
set company [optional|mandatory|...]
set email [disable|enable]
set expire {integer}
set expire-type [immediately|first-successful-login]
set group-type [firewall|fsso-service|...]
config guest
Description: Guest User.
edit <id>
set comment {var-string}
set company {string}
set email {string}
set expiration {user}
set mobile-phone {string}
set name {string}
set password {password}
set sponsor {string}
set user-id {string}
next
end
set http-digest-realm {string}
set id {integer}
config match
Description: Group matches.
edit <id>
set group-name {string}
set server-name {string}
next
end
set max-accounts {integer}
set member <name1>, <name2>, ...
set mobile-phone [disable|enable]
set multiple-guest-add [disable|enable]
set password [auto-generate|specify|...]
set sms-custom-server {string}
set sms-server [fortiguard|custom]
set sponsor [optional|mandatory|...]
set sso-attribute-value {string}
set user-id [email|auto-generate|...]
set user-name [disable|enable]
next
end

#### Parameters

config user group
Parameter Description Type Size Default
auth-
concurrent-
override
Enable/disable overriding the global number of
concurrent authentication sessions for this user
group.
option - disable
Option Description
enable Enable auth-concurrent-override.
disable Disable auth-concurrent-override.
auth-
concurrent-
value
Maximum number of concurrent authenticated
connections per user.
integer Minimum
value: 0
Maximum
value: 100
0
Parameter Description Type Size Default
authtimeout Authentication timeout in minutes for this user
group. 0 to use the global user setting auth-
timeout.
integer Minimum
value: 0
Maximum
value: 43200
0
company Set the action for the company guest user field. option - optional
Option Description
optional Optional.
mandatory Mandatory.
disabled Disabled.
email Enable/disable the guest user email address field. option - enable
Option Description
disable Disable setting.
enable Enable setting.
expire Time in seconds before guest user accounts
expire.
integer Minimum
value: 1
Maximum
value:
31536000
14400
expire-type Determine when the expiration countdown begins. option - immediately
Option Description
immediately Immediately.
first-successful-
login
First successful login.
group-type Set the group to be for firewall authentication,
FSSO, RSSO, or guest users.
option - firewall
Option Description
firewall Firewall.
fsso-service Fortinet Single Sign-On Service.
rsso RADIUS based Single Sign-On Service.
guest Guest.
http-digest-
realm
Realm attribute for MD5-digest authentication. string Maximum
length: 35
Parameter Description Type Size Default
id Group ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
max-accounts Maximum number of guest accounts that can be
created for this group (0 means unlimited).
integer Minimum
value: 0
Maximum
value: 1024 **
0
member
<name>
Names of users, peers, LDAP severs, RADIUS
servers or external idp servers to add to the user
group.
Group member name.
string Maximum
length: 511
mobile-phone Enable/disable the guest user mobile phone
number field.
option - disable
Option Description
disable Disable setting.
enable Enable setting.
multiple-
guest-add
Enable/disable addition of multiple guests. option - disable
Option Description
disable Disable setting.
enable Enable setting.
name Group name. string Maximum
length: 35
password Guest user password type. option - auto-generate
Option Description
auto-generate Automatically generate.
specify Specify.
disable Disable.
sms-custom-
server
SMS server. string Maximum
length: 35
sms-server Send SMS through FortiGuard or other external
server.
option - fortiguard
Parameter Description Type Size Default
Option Description
fortiguard Send SMS by FortiGuard.
custom Send SMS by custom server.
sponsor Set the action for the sponsor guest user field. option - optional
Option Description
optional Optional.
mandatory Mandatory.
disabled Disabled.
sso-attribute-
value
Name of the RADIUS user group that this local
user group represents.
string Maximum
length: 511
user-id Guest user ID type. option - email
Option Description
email Email address.
auto-generate Automatically generate.
specify Specify.
user-name Enable/disable the guest user name entry. option - disable
Option Description
disable Disable setting.
enable Enable setting.
** Values may differ between models.
config guest
Parameter Description Type Size Default
comment Comment. var-string Maximum
length: 255
company Set the action for the company guest user field. string Maximum
length: 35
email Email. string Maximum
length: 64
expiration Expire time. user Not Specified
Parameter Description Type Size Default
id Guest ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
mobile-phone Mobile phone. string Maximum
length: 35
name Guest name. string Maximum
length: 64
password Guest password. password Not Specified
sponsor Set the action for the sponsor guest user field. string Maximum
length: 35
user-id Guest ID. string Maximum
length: 64
config match
Parameter Description Type Size Default
group-name Name of matching user or group on remote
authentication server.
string Maximum
length: 511
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
server-name Name of remote auth server. string Maximum
length: 35

### config user krb-keytab

Configure Kerberos keytab entries.

#### Syntax

config user krb-keytab
Description: Configure Kerberos keytab entries.
edit <name>
set keytab {string}
set ldap-server <name1>, <name2>, ...
set pac-data [enable|disable]
set principal {string}
next
end

---

## config_user_local.md

# config user local

> Source: `config user local.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
Option Description
fortitoken FortiToken authentication.
email Email one time password.
sms SMS one time password.
two-factor-filter Filter used to
synchronize
users to
FortiToken
Cloud.
string Maximum
length:
2047
two-factor-
notification
Notification
method for user
activation by
FortiToken
Cloud.
option -
Option Description
email Email notification for activation code.
sms SMS notification for activation code.
type Authentication
type for LDAP
searches.
option - simple
Option Description
simple Simple password authentication without search.
anonymous Bind using anonymous user search.
regular Bind using username/password and then search.
user-info-
exchange-
server
MS Exchange
server from
which to fetch
user information.
string Maximum
length: 35
username Username (full
DN) for initial
binding.
string Maximum
length: 511

### config user local

Configure local users.

#### Syntax

config user local
Description: Configure local users.
edit <name>
set auth-concurrent-override [enable|disable]
set auth-concurrent-value {integer}
set authtimeout {integer}
set email-to {string}
set fortitoken {string}
set id {integer}
set ldap-server {string}
set passwd {password}
set passwd-policy {string}
set passwd-time {user}
set ppk-identity {string}
set ppk-secret {password-3}
set qkd-profile {string}
set radius-server {string}
set sms-custom-server {string}
set sms-phone {string}
set sms-server [fortiguard|custom]
set status [enable|disable]
set tacacs+-server {string}
set two-factor [disable|fortitoken|...]
set two-factor-authentication [fortitoken|email|...]
set two-factor-notification [email|sms]
set type [password|radius|...]
set username-sensitivity [disable|enable]
set workstation {string}
next
end

#### Parameters

config user local
Parameter Description Type Size Default
auth-concurrent-
override
Enable/disable overriding the policy-auth-
concurrent under config system global.
option - disable
Option Description
enable Enable auth-concurrent-override.
disable Disable auth-concurrent-override.
auth-concurrent-
value
Maximum number of concurrent logins permitted
from the same user.
integer Minimum
value: 0
Maximum
value: 100
0
authtimeout Time in minutes before the authentication timeout
for a user is reached.
integer Minimum
value: 0
Maximum
value: 1440
0
Parameter Description Type Size Default
email-to Two-factor recipient's email address. string Maximum
length: 63
fortitoken Two-factor recipient's FortiToken serial number. string Maximum
length: 16
id User ID. Read-only. integer Minimum
value: 0
Maximum
value:
4294967295
0
ldap-server Name of LDAP server with which the user must
authenticate.
string Maximum
length: 35
name Local user name. string Maximum
length: 64
passwd User's password. password Not Specified
passwd-policy Password policy to apply to this user, as defined
in config user password-policy.
string Maximum
length: 35
passwd-time Time of the last password update. user Not Specified
ppk-identity IKEv2 Postquantum Preshared Key Identity. string Maximum
length: 35
ppk-secret IKEv2 Postquantum Preshared Key (ASCII string
or hexadecimal encoded with a leading 0x).
password-3 Not Specified
qkd-profile Quantum Key Distribution (QKD) profile. string Maximum
length: 35
radius-server Name of RADIUS server with which the user must
authenticate.
string Maximum
length: 35
sms-custom-
server
Two-factor recipient's SMS server. string Maximum
length: 35
sms-phone Two-factor recipient's mobile phone number. string Maximum
length: 15
sms-server Send SMS through FortiGuard or other external
server.
option - fortiguard
Option Description
fortiguard Send SMS by FortiGuard.
custom Send SMS by custom server.
status Enable/disable allowing the local user to
authenticate with the FortiGate unit.
option - enable
Parameter Description Type Size Default
Option Description
enable Enable user.
disable Disable user.
tacacs+-server Name of TACACS+ server with which the user
must authenticate.
string Maximum
length: 35
two-factor Enable/disable two-factor authentication. option - disable
Option Description
disable disable
fortitoken FortiToken
fortitoken-cloud FortiToken Cloud Service.
email Email authentication code.
sms SMS authentication code.
two-factor-
authentication
Authentication method by FortiToken Cloud. option -
Option Description
fortitoken FortiToken authentication.
email Email one time password.
sms SMS one time password.
two-factor-
notification
Notification method for user activation by
FortiToken Cloud.
option -
Option Description
email Email notification for activation code.
sms SMS notification for activation code.
type Authentication method. option - password
Option Description
password Password authentication.
radius RADIUS server authentication.
tacacs+ TACACS+ server authentication.
ldap LDAP server authentication.
Parameter Description Type Size Default
username-
sensitivity
Enable/disable case and accent sensitivity when
performing username matching (accents are
stripped and case is ignored when disabled).
option - enable
Option Description
disable Ignore case and accents. Username at prompt not required to match case or
accents.
enable Do not ignore case and accents. Username at prompt must be an exact
match.
workstation Name of the remote user workstation, if you want
to limit the user to authenticate only from a
particular workstation.
string Maximum
length: 35

### config user nac-policy

Configure NAC policy matching pattern to identify matching NAC devices.

#### Syntax

config user nac-policy
Description: Configure NAC policy matching pattern to identify matching NAC devices.
edit <name>
set category [device|firewall-user|...]
set description {string}
set ems-tag {string}
set family {string}
set firewall-address {string}
set fortivoice-tag {string}
set host {string}
set hw-vendor {string}
set hw-version {string}
set mac {string}
set match-period {integer}
set match-type [dynamic|override]
set os {string}
set severity <severity-num1>, <severity-num2>, ...
set src {string}
set ssid-policy {string}
set status [enable|disable]
set sw-version {string}
set switch-fortilink {string}
set switch-group <name1>, <name2>, ...
set switch-mac-policy {string}
set type {string}
set user {string}
set user-group {string}
next
end

---

## config_vpn_phase_1_and_2.md

# config vpn phase 1 and 2

> Source: `config vpn phase 1 and 2.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

Parameter Description Type Size Default
npu-offload * Enable/disable NPU offloading. option - enable
Option Description
enable Enable NPU offloading.
disable Disable NPU offloading.
remote-gw Peer gateway. ipv4-
address
Not
Specified
0.0.0.0
remotespi Remote SPI, a hexadecimal 8-digit (4-byte) tag.
Discerns between two traffic streams with different
encryption rules.
user Not
Specified
- This parameter may not exist in some models.

### config vpn ipsec phase1-interface

Configure VPN remote gateway.

#### Syntax

config vpn ipsec phase1-interface
Description: Configure VPN remote gateway.
edit <name>
set acct-verify [enable|disable]
set add-gw-route [enable|disable]
set add-route [disable|enable]
set aggregate-member [enable|disable]
set aggregate-weight {integer}
set assign-ip [disable|enable]
set assign-ip-from [range|usrgrp|...]
set authmethod [psk|signature]
set authmethod-remote [psk|signature]
set authpasswd {password}
set authusr {string}
set authusrgrp {string}
set auto-discovery-crossover [allow|block]
set auto-discovery-forwarder [enable|disable]
set auto-discovery-offer-interval {integer}
set auto-discovery-psk [enable|disable]
set auto-discovery-receiver [enable|disable]
set auto-discovery-sender [enable|disable]
set auto-discovery-shortcuts [independent|dependent]
set auto-negotiate [enable|disable]
set azure-ad-autoconnect [enable|disable]
set backup-gateway <address1>, <address2>, ...
set banner {var-string}
set cert-id-validation [enable|disable]
set cert-peer-username-strip [disable|enable]
set cert-peer-username-validation [none|othername|...]
set cert-trust-store [local|ems]
set certificate <name1>, <name2>, ...
set childless-ike [enable|disable]
set client-auto-negotiate [disable|enable]
set client-keep-alive [disable|enable]
set client-resume [enable|disable]
set client-resume-interval {integer}
set comments {var-string}
set default-gw {ipv4-address}
set default-gw-priority {integer}
set dev-id {string}
set dev-id-notification [disable|enable]
set dhcp-ra-giaddr {ipv4-address}
set dhcp6-ra-linkaddr {ipv6-address}
set dhgrp {option1}, {option2}, ...
set digital-signature-auth [enable|disable]
set distance {integer}
set dns-mode [manual|auto]
set domain {string}
set dpd [disable|on-idle|...]
set dpd-retrycount {integer}
set dpd-retryinterval {user}
set eap [enable|disable]
set eap-cert-auth [enable|disable]
set eap-exclude-peergrp {string}
set eap-identity [use-id-payload|send-request]
set ems-sn-check [enable|disable]
set encap-local-gw4 {ipv4-address}
set encap-local-gw6 {ipv6-address}
set encap-remote-gw4 {ipv4-address}
set encap-remote-gw6 {ipv6-address}
set encapsulation [none|gre|...]
set encapsulation-address [ike|ipv4|...]
set enforce-unique-id [disable|keep-new|...]
set esn [require|allow|...]
set exchange-fgt-device-id [enable|disable]
set exchange-interface-ip [enable|disable]
set exchange-ip-addr4 {ipv4-address}
set exchange-ip-addr6 {ipv6-address}
set fallback-tcp-threshold {integer}
set fec-base {integer}
set fec-codec [rs|xor]
set fec-egress [enable|disable]
set fec-health-check {string}
set fec-ingress [enable|disable]
set fec-mapping-profile {string}
set fec-receive-timeout {integer}
set fec-redundant {integer}
set fec-send-timeout {integer}
set fgsp-sync [enable|disable]
set fortinet-esp [enable|disable]
set fragmentation [enable|disable]
set fragmentation-mtu {integer}
set group-authentication [enable|disable]
set group-authentication-secret {password-3}
set ha-sync-esp-seqno [enable|disable]
set idle-timeout [enable|disable]
set idle-timeoutinterval {integer}
set ike-version [1|2]
set inbound-dscp-copy [enable|disable]
set include-local-lan [disable|enable]
set interface {string}
set internal-domain-list <domain-name1>, <domain-name2>, ...
set ip-delay-interval {integer}
set ip-fragmentation [pre-encapsulation|post-encapsulation]
set ip-version [4|6]
set ipv4-dns-server1 {ipv4-address}
set ipv4-dns-server2 {ipv4-address}
set ipv4-dns-server3 {ipv4-address}
set ipv4-end-ip {ipv4-address}
config ipv4-exclude-range
Description: Configuration Method IPv4 exclude ranges.
edit <id>
set end-ip {ipv4-address}
set start-ip {ipv4-address}
next
end
set ipv4-name {string}
set ipv4-netmask {ipv4-netmask}
set ipv4-split-exclude {string}
set ipv4-split-include {string}
set ipv4-start-ip {ipv4-address}
set ipv4-wins-server1 {ipv4-address}
set ipv4-wins-server2 {ipv4-address}
set ipv6-dns-server1 {ipv6-address}
set ipv6-dns-server2 {ipv6-address}
set ipv6-dns-server3 {ipv6-address}
set ipv6-end-ip {ipv6-address}
config ipv6-exclude-range
Description: Configuration method IPv6 exclude ranges.
edit <id>
set end-ip {ipv6-address}
set start-ip {ipv6-address}
next
end
set ipv6-name {string}
set ipv6-prefix {integer}
set ipv6-split-exclude {string}
set ipv6-split-include {string}
set ipv6-start-ip {ipv6-address}
set keepalive {integer}
set keylife {integer}
set kms {string}
set link-cost {integer}
set local-gw {ipv4-address}
set local-gw6 {ipv6-address}
set localid {string}
set localid-type [auto|fqdn|...]
set loopback-asymroute [enable|disable]
set mesh-selector-type [disable|subnet|...]
set mode [aggressive|main]
set mode-cfg [disable|enable]
set mode-cfg-allow-client-selector [disable|enable]
set monitor <name1>, <name2>, ...
set monitor-hold-down-delay {integer}
set monitor-hold-down-time {user}
set monitor-hold-down-type [immediate|delay|...]
set monitor-hold-down-weekday [everyday|sunday|...]
set monitor-min {integer}
set nattraversal [enable|disable|...]
set negotiate-timeout {integer}
set net-device [enable|disable]
set network-id {integer}
set network-overlay [disable|enable]
set npu-offload [enable|disable]
set packet-redistribution [enable|disable]
set passive-mode [enable|disable]
set peer {string}
set peergrp {string}
set peerid {string}
set peertype [any|one|...]
set ppk [disable|allow|...]
set ppk-identity {string}
set ppk-secret {password-3}
set priority {integer}
set proposal {option1}, {option2}, ...
set psksecret {password-3}
set psksecret-remote {password-3}
set qkd [disable|allow|...]
set qkd-profile {string}
set reauth [disable|enable]
set rekey [enable|disable]
set remote-gw {ipv4-address}
set remote-gw-country {string}
set remote-gw-end-ip {ipv4-address-any}
set remote-gw-match [any|ipmask|...]
set remote-gw-start-ip {ipv4-address-any}
set remote-gw-subnet {ipv4-classnet-any}
set remote-gw6 {ipv6-address}
set remote-gw6-country {string}
set remote-gw6-end-ip {ipv6-address}
set remote-gw6-match [any|ipprefix|...]
set remote-gw6-start-ip {ipv6-address}
set remote-gw6-subnet {ipv6-network}
set remotegw-ddns {string}
set rsa-signature-format [pkcs1|pss]
set rsa-signature-hash-override [enable|disable]
set save-password [disable|enable]
set send-cert-chain [enable|disable]
set signature-hash-alg {option1}, {option2}, ...
set split-include-service {string}
set suite-b [disable|suite-b-gcm-128|...]
set transport [udp|udp-fallback-tcp|...]
set type [static|dynamic|...]
set unity-support [disable|enable]
set usrgrp {string}
set vni {integer}
set wizard-type [custom|dialup-forticlient|...]
set xauthtype [disable|client|...]
next
end

#### Parameters

config vpn ipsec phase1-interface
Parameter Description Type Size Default
acct-verify Enable/disable verification of RADIUS
accounting record.
option - disable
Option Description
enable Enable verification of RADIUS accounting record.
disable Disable verification of RADIUS accounting record.
add-gw-route Enable/disable automatically add a route
to the remote gateway.
option - disable
Option Description
enable Automatically add a route to the remote gateway.
disable Do not automatically add a route to the remote gateway.
add-route Enable/disable control addition of a route
to peer destination selector.
option - enable
Option Description
disable Do not add a route to destination of peer selector.
enable Add route to destination of peer selector.
aggregate-
member
Enable/disable use as an aggregate
member.
option - disable
Option Description
enable Enable use as an aggregate member.
disable Disable use as an aggregate member.
aggregate-
weight
Link weight for aggregate. integer Minimum
value: 1
Maximum
value: 100
1
assign-ip Enable/disable assignment of IP to IPsec
interface via configuration method.
option - enable
Option Description
disable Do not assign an IP address to the IPsec interface.
enable Assign an IP address to the IPsec interface.
assign-ip-from Method by which the IP address will be
assigned.
option - range
Parameter Description Type Size Default
Option Description
range Assign IP address from locally defined range.
usrgrp Assign IP address via user group.
dhcp Assign IP address via DHCP.
name Assign IP address from firewall address or group.
authmethod Authentication method. option - psk
Option Description
psk PSK authentication method.
signature Signature authentication method.
authmethod-
remote
Authentication method (remote side). option -
Option Description
psk PSK authentication method.
signature Signature authentication method.
authpasswd XAuth password (max 35 characters). password Not Specified
authusr XAuth user name. string Maximum
length: 64
authusrgrp Authentication user group. string Maximum
length: 35
auto-discovery-
crossover
Allow/block set-up of short-cut tunnels
between different network IDs.
option - allow
Option Description
allow Allow set-up of short-cut tunnels between different network IDs.
block Block set-up of short-cut tunnels between different network IDs.
auto-discovery-
forwarder
Enable/disable forwarding auto-discovery
short-cut messages.
option - disable
Option Description
enable Enable forwarding auto-discovery short-cut messages.
disable Disable forwarding auto-discovery short-cut messages.
Parameter Description Type Size Default
auto-discovery-
offer-interval
Interval between shortcut offer messages
in seconds.
integer Minimum
value: 1
Maximum
value: 300
5
auto-discovery-
psk
Enable/disable use of pre-shared secrets
for authentication of auto-discovery
tunnels.
option - disable
Option Description
enable Enable use of pre-shared-secret authentication for auto-discovery tunnels.
disable Disable use of authentication defined by 'authmethod' for auto-discovery
tunnels.
auto-discovery-
receiver
Enable/disable accepting auto-discovery
short-cut messages.
option - disable
Option Description
enable Enable receiving auto-discovery short-cut messages.
disable Disable receiving auto-discovery short-cut messages.
auto-discovery-
sender
Enable/disable sending auto-discovery
short-cut messages.
option - disable
Option Description
enable Enable sending auto-discovery short-cut messages.
disable Disable sending auto-discovery short-cut messages.
auto-discovery-
shortcuts
Control deletion of child short-cut tunnels
when the parent tunnel goes down.
option - independent
Option Description
independent Short-cut tunnels remain up if the parent tunnel goes down.
dependent Short-cut tunnels are brought down if the parent tunnel goes down.
auto-negotiate Enable/disable automatic initiation of IKE
SA negotiation.
option - enable
Option Description
enable Enable automatic initiation of IKE SA negotiation.
disable Disable automatic initiation of IKE SA negotiation.
Parameter Description Type Size Default
azure-ad-
autoconnect
Enable/disable Azure AD Auto-Connect
for FortiClient.
option - disable
Option Description
enable Enable Azure AD Auto-Connect for FortiClient.
disable Disable Azure AD Auto-Connect for FortiClient.
backup-gateway
<address>
Instruct unity clients about the backup
gateway address(es).
Address of backup gateway.
string Maximum
length: 79
banner Message that unity client should display
after connecting.
var-string Maximum
length: 1024
cert-id-validation Enable/disable cross validation of peer ID
and the identity in the peer's certificate as
specified in RFC 4945.
option - enable
Option Description
enable Enable cross validation of peer ID and the identity in the peer's certificate as
specified in RFC 4945.
disable Disable cross validation of peer ID and the identity in the peer's certificate
as specified in RFC 4945.
cert-peer-
username-strip
Enable/disable domain stripping on
certificate identity.
option - disable
Option Description
disable Disable domain stripping on certificate identity.
enable Enable domain stripping on certificate identity.
cert-peer-
username-
validation
Enable/disable cross validation of peer
username and the identity in the peer's
certificate.
option - none
Option Description
none Disable cross validation of peer username and the identity in the peer's
certificate.
othername Validate principal name in SAN othername.
rfc822name Validate RFC822 email address in SAN.
cn Validate CN in subject.
cert-trust-store CA certificate trust store. option - local
Parameter Description Type Size Default
Option Description
local Use local CA certificate.
ems Use EMS CA certificate.
certificate
<name>
The names of up to 4 signed personal
certificates.
Certificate name.
string Maximum
length: 79
childless-ike Enable/disable childless IKEv2 initiation
(RFC 6023).
option - disable
Option Description
enable Enable childless IKEv2 initiation (RFC 6023).
disable Disable childless IKEv2 initiation (RFC 6023).
client-auto-
negotiate
Enable/disable allowing the VPN client to
bring up the tunnel when there is no
traffic.
option - disable
Option Description
disable Disable allowing the VPN client to bring up the tunnel when there is no
traffic.
enable Enable allowing the VPN client to bring up the tunnel when there is no
traffic.
client-keep-alive Enable/disable allowing the VPN client to
keep the tunnel up when there is no
traffic.
option - disable
Option Description
disable Disable allowing the VPN client to keep the tunnel up when there is no
traffic.
enable Enable allowing the VPN client to keep the tunnel up when there is no
traffic.
client-resume Enable/disable resumption of offline
FortiClient sessions. When a FortiClient
enabled laptop is closed or enters
sleep/hibernate mode, enabling this
feature allows FortiClient to keep the
tunnel during this period, and allows
users to immediately resume using the
IPsec tunnel when the device wakes up.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable client session resumption.
disable Disable client session resumption.
client-resume-
interval
Maximum time in seconds during which a
VPN client may resume using a tunnel
after a client PC has entered sleep mode
or temporarily lost its network connection.
integer Minimum
value: 120
Maximum
value: 172800
7200
comments Comment. var-string Maximum
length: 255
default-gw IPv4 address of default route gateway to
use for traffic exiting the interface.
ipv4-address Not Specified 0.0.0.0
default-gw-
priority
Priority for default gateway route. A
higher priority number signifies a less
preferred route.
integer Minimum
value: 0
Maximum
value:
4294967295
0
dev-id Device ID carried by the device ID
notification.
string Maximum
length: 63
dev-id-
notification
Enable/disable device ID notification. option - disable
Option Description
disable Disable device ID notification.
enable Enable device ID notification.
dhcp-ra-giaddr Relay agent gateway IP address to use in
the giaddr field of DHCP requests.
ipv4-address Not Specified 0.0.0.0
dhcp6-ra-
linkaddr
Relay agent IPv6 link address to use in
DHCP6 requests.
ipv6-address Not Specified ::
dhgrp DH group. option - 14
Option Description
1 DH Group 1.
2 DH Group 2.
5 DH Group 5.
14 DH Group 14.
15 DH Group 15.
Parameter Description Type Size Default
Option Description
16 DH Group 16.
17 DH Group 17.
18 DH Group 18.
19 DH Group 19.
20 DH Group 20.
21 DH Group 21.
27 DH Group 27.
28 DH Group 28.
29 DH Group 29.
30 DH Group 30.
31 DH Group 31.
32 DH Group 32.
digital-signature-
auth
Enable/disable IKEv2 Digital Signature
Authentication (RFC 7427).
option - disable
Option Description
enable Enable IKEv2 Digital Signature Authentication (RFC 7427).
disable Disable IKEv2 Digital Signature Authentication (RFC 7427).
distance Distance for routes added by IKE. integer Minimum
value: 1
Maximum
value: 255
15
dns-mode DNS server mode. option - manual
Option Description
manual Manually configure DNS servers.
auto Use default DNS servers.
domain Instruct unity clients about the single
default DNS domain.
string Maximum
length: 63
dpd Dead Peer Detection mode. option - on-demand
Parameter Description Type Size Default
Option Description
disable Disable Dead Peer Detection.
on-idle Trigger Dead Peer Detection when IPsec is idle.
on-demand Trigger Dead Peer Detection when IPsec traffic is sent but no reply is
received from the peer.
dpd-retrycount Number of DPD retry attempts. integer Minimum
value: 0
Maximum
value: 10
3
dpd-retryinterval DPD retry interval. user Not Specified
eap Enable/disable IKEv2 EAP
authentication.
option - disable
Option Description
enable Enable IKEv2 EAP authentication.
disable Disable IKEv2 EAP authentication.
eap-cert-auth Enable/disable peer certificate
authentication in addition to EAP if peer is
a FortiClient endpoint.
option - disable
Option Description
enable Enable peer certificate authentication in addition to EAP if peer is a
FortiClient endpoint.
disable Disable peer certificate authentication in addition to EAP if peer is a
FortiClient endpoint.
eap-exclude-
peergrp
Peer group excluded from EAP
authentication.
string Maximum
length: 35
eap-identity IKEv2 EAP peer identity type. option - use-id-payload
Option Description
use-id-payload Use IKEv2 IDi payload to resolve peer identity.
send-request Use EAP identity request to resolve peer identity.
ems-sn-check Enable/disable verification of EMS serial
number.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable EMS serial number verification.
disable Disable EMS serial number verification.
encap-local-gw4 Local IPv4 address of GRE/VXLAN
tunnel.
ipv4-address Not Specified 0.0.0.0
encap-local-gw6 Local IPv6 address of GRE/VXLAN
tunnel.
ipv6-address Not Specified ::
encap-remote-
gw4
Remote IPv4 address of GRE/VXLAN
tunnel.
ipv4-address Not Specified 0.0.0.0
encap-remote-
gw6
Remote IPv6 address of GRE/VXLAN
tunnel.
ipv6-address Not Specified ::
encapsulation Enable/disable GRE/VXLAN/VPNID
encapsulation.
option - none
Option Description
none No additional encapsulation.
gre GRE encapsulation.
vxlan VXLAN encapsulation.
vpn-id-ipip VPN ID with IPIP encapsulation.
encapsulation-
address
Source for GRE/VXLAN tunnel address. option - ike
Option Description
ike Use IKE/IPsec gateway addresses.
ipv4 Specify separate GRE/VXLAN tunnel address.
ipv6 Specify separate GRE/VXLAN tunnel address.
enforce-unique-
id
Enable/disable peer ID uniqueness
check.
option - disable
Option Description
disable Disable peer ID uniqueness enforcement.
keep-new Enforce peer ID uniqueness, keep new connection if collision found.
keep-old Enforce peer ID uniqueness, keep old connection if collision found.
Parameter Description Type Size Default
esn * Extended sequence number (ESN)
negotiation.
option - disable
Option Description
require Require extended sequence number.
allow Allow extended sequence number.
disable Disable extended sequence number.
exchange-fgt-
device-id
Enable/disable device identifier exchange
with peer FortiGate units for use of VPN
monitor data by FortiManager.
option - disable
Option Description
enable Enable exchange of FortiGate device identifier.
disable Disable exchange of FortiGate device identifier.
exchange-
interface-ip
Enable/disable exchange of IPsec
interface IP address.
option - disable
Option Description
enable Enable exchange of IPsec interface IP address.
disable Disable exchange of IPsec interface IP address.
exchange-ip-
addr4
IPv4 address to exchange with peers. ipv4-address Not Specified 0.0.0.0
exchange-ip-
addr6
IPv6 address to exchange with peers. ipv6-address Not Specified ::
fallback-tcp-
threshold
Timeout in seconds before falling back
IKE/IPsec traffic to tcp.
integer Minimum
value: 1
Maximum
value: 300
15
fec-base Number of base Forward Error Correction
packets.
integer Minimum
value: 1
Maximum
value: 20
10
fec-codec Forward Error Correction
encoding/decoding algorithm.
option - rs
Option Description
rs Reed-Solomon FEC algorithm.
Parameter Description Type Size Default
Option Description
xor XOR FEC algorithm.
fec-egress Enable/disable Forward Error Correction
for egress IPsec traffic.
option - disable
Option Description
enable Enable Forward Error Correction for egress IPsec traffic.
disable Disable Forward Error Correction for egress IPsec traffic.
fec-health-check SD-WAN health check. string Maximum
length: 35
fec-ingress Enable/disable Forward Error Correction
for ingress IPsec traffic.
option - disable
Option Description
enable Enable Forward Error Correction for ingress IPsec traffic.
disable Disable Forward Error Correction for ingress IPsec traffic.
fec-mapping-
profile
Forward Error Correction (FEC) mapping
profile.
string Maximum
length: 35
fec-receive-
timeout
Timeout in milliseconds before dropping
Forward Error Correction packets.
integer Minimum
value: 1
Maximum
value: 1000
50
fec-redundant Number of redundant Forward Error
Correction packets.
integer Minimum
value: 1
Maximum
value: 5
1
fec-send-timeout Timeout in milliseconds before sending
Forward Error Correction packets.
integer Minimum
value: 1
Maximum
value: 1000
5
fgsp-sync Enable/disable IPsec syncing of tunnels
for FGSP IPsec.
option - disable
Option Description
enable Enable IPsec syncing of tunnels to other cluster members.
disable Disable IPsec syncing of tunnels to other cluster members.
Parameter Description Type Size Default
fortinet-esp Enable/disable Fortinet ESP
encapsulaton.
option - disable
Option Description
enable Enable Fortinet ESP encapsulation.
disable Disable Fortinet ESP encapsulaton.
fragmentation Enable/disable fragment IKE message on
re-transmission.
option - enable
Option Description
enable Enable intra-IKE fragmentation support on re-transmission.
disable Disable intra-IKE fragmentation support.
fragmentation-
mtu
IKE fragmentation MTU. integer Minimum
value: 500
Maximum
value: 16000
1200
group-
authentication
Enable/disable IKEv2 IDi group
authentication.
option - disable
Option Description
enable Enable IKEv2 IDi group authentication.
disable Disable IKEv2 IDi group authentication.
group-
authentication-
secret
Password for IKEv2 ID group
authentication. ASCII string or
hexadecimal indicated by a leading 0x.
password-3 Not Specified
ha-sync-esp-
seqno
Enable/disable sequence number jump
ahead for IPsec HA.
option - enable
Option Description
enable Enable HA syncing of ESP sequence numbers.
disable Disable HA syncing of ESP sequence numbers.
idle-timeout Enable/disable IPsec tunnel idle timeout. option - disable
Option Description
enable Enable IPsec tunnel idle timeout.
disable Disable IPsec tunnel idle timeout.
Parameter Description Type Size Default
idle-
timeoutinterval
IPsec tunnel idle timeout in minutes. integer Minimum
value: 5
Maximum
value: 43200
15
ike-version IKE protocol version. option - 1
Option Description
1 Use IKEv1 protocol.
2 Use IKEv2 protocol.
inbound-dscp-
copy
Enable/disable copy the dscp in the ESP
header to the inner IP Header.
option - disable
Option Description
enable Enable copy the dscp in the ESP header to the inner IP Header.
disable Disable copy the dscp in the ESP header to the inner IP Header.
include-local-lan Enable/disable allow local LAN access on
unity clients.
option - disable
Option Description
disable Disable local LAN access on Unity clients.
enable Enable local LAN access on Unity clients.
interface Local physical, aggregate, or VLAN
outgoing interface.
string Maximum
length: 35
internal-domain-
list <domain-
name>
One or more internal domain names in
quotes separated by spaces.
Domain name.
string Maximum
length: 79
ip-delay-interval IP address reuse delay interval in
seconds.
integer Minimum
value: 0
Maximum
value: 28800
0
ip-fragmentation Determine whether IP packets are
fragmented before or after IPsec
encapsulation.
option - post-encapsulation
Option Description
pre-
encapsulation
Fragment before IPsec encapsulation.
Parameter Description Type Size Default
Option Description
post-
encapsulation
Fragment after IPsec encapsulation (RFC compliant).
ip-version IP version to use for VPN interface. option - 4
Option Description
4 Use IPv4 addressing for gateways.
6 Use IPv6 addressing for gateways.
ipv4-dns-server1 IPv4 DNS server 1. ipv4-address Not Specified 0.0.0.0
ipv4-dns-server2 IPv4 DNS server 2. ipv4-address Not Specified 0.0.0.0
ipv4-dns-server3 IPv4 DNS server 3. ipv4-address Not Specified 0.0.0.0
ipv4-end-ip End of IPv4 range. ipv4-address Not Specified 0.0.0.0
ipv4-name IPv4 address name. string Maximum
length: 79
ipv4-netmask IPv4 Netmask. ipv4-
netmask
Not Specified 255.255.255.255
ipv4-split-
exclude
IPv4 subnets that should not be sent over
the IPsec tunnel.
string Maximum
length: 79
ipv4-split-include IPv4 split-include subnets. string Maximum
length: 79
ipv4-start-ip Start of IPv4 range. ipv4-address Not Specified 0.0.0.0
ipv4-wins-
server1
WINS server 1. ipv4-address Not Specified 0.0.0.0
ipv4-wins-
server2
WINS server 2. ipv4-address Not Specified 0.0.0.0
ipv6-dns-server1 IPv6 DNS server 1. ipv6-address Not Specified ::
ipv6-dns-server2 IPv6 DNS server 2. ipv6-address Not Specified ::
ipv6-dns-server3 IPv6 DNS server 3. ipv6-address Not Specified ::
ipv6-end-ip End of IPv6 range. ipv6-address Not Specified ::
ipv6-name IPv6 address name. string Maximum
length: 79
Parameter Description Type Size Default
ipv6-prefix IPv6 prefix. integer Minimum
value: 1
Maximum
value: 128
128
ipv6-split-
exclude
IPv6 subnets that should not be sent over
the IPsec tunnel.
string Maximum
length: 79
ipv6-split-include IPv6 split-include subnets. string Maximum
length: 79
ipv6-start-ip Start of IPv6 range. ipv6-address Not Specified ::
keepalive NAT-T keep alive interval. integer Minimum
value: 5
Maximum
value: 900
10
keylife Time to wait in seconds before phase 1
encryption key expires.
integer Minimum
value: 120
Maximum
value: 172800
86400
kms Key Management Services server. string Maximum
length: 35
link-cost VPN tunnel underlay link cost. integer Minimum
value: 0
Maximum
value: 255
0
local-gw IPv4 address of the local gateway's
external interface.
ipv4-address Not Specified 0.0.0.0
local-gw6 IPv6 address of the local gateway's
external interface.
ipv6-address Not Specified ::
localid Local ID. string Maximum
length: 63
localid-type Local ID type. option - auto
Option Description
auto Select ID type automatically.
fqdn Use fully qualified domain name.
user-fqdn Use user fully qualified domain name.
keyid Use key-id string.
address Use local IP address.
asn1dn Use ASN.1 distinguished name.
Parameter Description Type Size Default
loopback-
asymroute
Enable/disable asymmetric routing for
IKE traffic on loopback interface.
option - enable
Option Description
enable Allow ingress/egress IKE traffic to be routed over different interfaces.
disable Ingress/egress IKE traffic must be routed over the same interface.
mesh-selector-
type
Add selectors containing subsets of the
configuration depending on traffic.
option - disable
Option Description
disable Disable.
subnet Enable addition of matching subnet selector.
host Enable addition of host to host selector.
mode The ID protection mode used to establish
a secure channel.
option - main
Option Description
aggressive Aggressive mode.
main Main mode.
mode-cfg Enable/disable configuration method. option - disable
Option Description
disable Disable Configuration Method.
enable Enable Configuration Method.
mode-cfg-allow-
client-selector
Enable/disable mode-cfg client to use
custom phase2 selectors.
option - disable
Option Description
disable Mode-cfg client to use wildcard selectors.
enable Mode-cfg client to use custom selectors.
monitor <name> IPsec interface as backup for primary
interface.
IPsec interface as backup for primary
interface.
string Maximum
length: 79
Parameter Description Type Size Default
monitor-hold-
down-delay
Time to wait in seconds before recovery
once primary re-establishes.
integer Minimum
value: 0
Maximum
value:
31536000
0
monitor-hold-
down-time
Time of day at which to fail back to
primary after it re-establishes.
user Not Specified
monitor-hold-
down-type
Recovery time method when primary
interface re-establishes.
option - immediate
Option Description
immediate Fail back immediately after primary recovers.
delay Number of seconds to delay fail back after primary recovers.
time Specify a time at which to fail back after primary recovers.
monitor-hold-
down-weekday
Day of the week to recover once primary
re-establishes.
option - sunday
Option Description
everyday Every Day.
sunday Sunday.
monday Monday.
tuesday Tuesday.
wednesday Wednesday.
thursday Thursday.
friday Friday.
saturday Saturday.
monitor-min Minimum number of links to become
degraded before activating this interface.
Zero (0) means all links must be down
before activating this interface.
integer Minimum
value: 0
Maximum
value:
4294967295
0
name IPsec remote gateway name. string Maximum
length: 15
nattraversal Enable/disable NAT traversal. option - enable
Parameter Description Type Size Default
Option Description
enable Enable IPsec NAT traversal.
disable Disable IPsec NAT traversal.
forced Force IPsec NAT traversal on.
negotiate-
timeout
IKE SA negotiation timeout in seconds. integer Minimum
value: 1
Maximum
value: 300
30
net-device Enable/disable kernel device creation. option - disable
Option Description
enable Create a kernel device for every tunnel.
disable Do not create a kernel device for tunnels.
network-id VPN gateway network ID. integer Minimum
value: 0
Maximum
value: 255
0
network-overlay Enable/disable network overlays. option - disable
Option Description
disable Disable network overlays.
enable Enable network overlays.
npu-offload * Enable/disable offloading NPU. option - enable
Option Description
enable Enable NPU offloading.
disable Disable NPU offloading.
packet-
redistribution *
Enable/disable packet distribution (RPS)
on the IPsec interface.
option - disable
Option Description
enable Enable packet redistribution.
disable Disable packet redistribution.
passive-mode Enable/disable IPsec passive mode for
static tunnels.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable IPsec passive mode.
disable Disable IPsec passive mode.
peer Accept this peer certificate. string Maximum
length: 35
peergrp Accept this peer certificate group. string Maximum
length: 35
peerid Accept this peer identity. string Maximum
length: 255
peertype Accept this peer type. option - peer
Option Description
any Accept any peer ID.
one Accept this peer ID.
dialup Accept peer ID in dialup group.
peer Accept this peer certificate.
peergrp Accept this peer certificate group.
ppk Enable/disable IKEv2 Postquantum
Preshared Key (PPK).
option - disable
Option Description
disable Disable use of IKEv2 Postquantum Preshared Key (PPK).
allow Allow, but do not require, use of IKEv2 Postquantum Preshared Key (PPK).
require Require use of IKEv2 Postquantum Preshared Key (PPK).
ppk-identity IKEv2 Postquantum Preshared Key
Identity.
string Maximum
length: 35
ppk-secret IKEv2 Postquantum Preshared Key
(ASCII string or hexadecimal encoded
with a leading 0x).
password-3 Not Specified
priority Priority for routes added by IKE. integer Minimum
value: 1
Maximum
value: 65535
1
proposal Phase1 proposal. option -
Parameter Description Type Size Default
Option Description
des-md5 des-md5
des-sha1 des-sha1
des-sha256 des-sha256
des-sha384 des-sha384
des-sha512 des-sha512
3des-md5 3des-md5
3des-sha1 3des-sha1
3des-sha256 3des-sha256
3des-sha384 3des-sha384
3des-sha512 3des-sha512
aes128-md5 aes128-md5
aes128-sha1 aes128-sha1
aes128-sha256 aes128-sha256
aes128-sha384 aes128-sha384
aes128-sha512 aes128-sha512
aes128gcm-prfsha1 aes128gcm-prfsha1
aes128gcm-prfsha256 aes128gcm-prfsha256
aes128gcm-prfsha384 aes128gcm-prfsha384
aes128gcm-prfsha512 aes128gcm-prfsha512
aes192-md5 aes192-md5
aes192-sha1 aes192-sha1
aes192-sha256 aes192-sha256
aes192-sha384 aes192-sha384
aes192-sha512 aes192-sha512
aes256-md5 aes256-md5
aes256-sha1 aes256-sha1
aes256-sha256 aes256-sha256
aes256-sha384 aes256-sha384
aes256-sha512 aes256-sha512
Parameter Description Type Size Default
Option Description
aes256gcm-prfsha1 aes256gcm-prfsha1
aes256gcm-prfsha256 aes256gcm-prfsha256
aes256gcm-prfsha384 aes256gcm-prfsha384
aes256gcm-prfsha512 aes256gcm-prfsha512
chacha20poly1305-prfsha1 chacha20poly1305-prfsha1
chacha20poly1305-prfsha256 chacha20poly1305-prfsha256
chacha20poly1305-prfsha384 chacha20poly1305-prfsha384
chacha20poly1305-prfsha512 chacha20poly1305-prfsha512
aria128-md5 aria128-md5
aria128-sha1 aria128-sha1
aria128-sha256 aria128-sha256
aria128-sha384 aria128-sha384
aria128-sha512 aria128-sha512
aria192-md5 aria192-md5
aria192-sha1 aria192-sha1
aria192-sha256 aria192-sha256
aria192-sha384 aria192-sha384
aria192-sha512 aria192-sha512
aria256-md5 aria256-md5
aria256-sha1 aria256-sha1
aria256-sha256 aria256-sha256
aria256-sha384 aria256-sha384
aria256-sha512 aria256-sha512
seed-md5 seed-md5
seed-sha1 seed-sha1
seed-sha256 seed-sha256
seed-sha384 seed-sha384
seed-sha512 seed-sha512
Parameter Description Type Size Default
psksecret Pre-shared secret for PSK authentication
(ASCII string or hexadecimal encoded
with a leading 0x).
password-3 Not Specified
psksecret-
remote
Pre-shared secret for remote side PSK
authentication (ASCII string or
hexadecimal encoded with a leading 0x).
password-3 Not Specified
qkd Enable/disable use of Quantum Key
Distribution (QKD) server.
option - disable
Option Description
disable Disable use of a Quantum Key Distribution (QKD) server.
allow Allow, but do not require, use of a Quantum Key Distribution (QKD) server.
require Require use of a Quantum Key Distribution (QKD) server.
qkd-profile Quantum Key Distribution (QKD) server
profile.
string Maximum
length: 35
reauth Enable/disable re-authentication upon
IKE SA lifetime expiration.
option - disable
Option Description
disable Disable IKE SA re-authentication.
enable Enable IKE SA re-authentication.
rekey Enable/disable phase1 rekey. option - enable
Option Description
enable Enable phase1 rekey.
disable Disable phase1 rekey.
remote-gw IPv4 address of the remote gateway's
external interface.
ipv4-address Not Specified 0.0.0.0
remote-gw-
country
IPv4 addresses associated to a specific
country.
string Maximum
length: 2
remote-gw-end-
ip
Last IPv4 address in the range. ipv4-
address-any
Not Specified 0.0.0.0
remote-gw-
match
Set type of IPv4 remote gateway address
matching.
option - any
Parameter Description Type Size Default
Option Description
any Match any IPv4 gateway address.
ipmask Match IPv4 gateway address and mask.
iprange Match IPv4 gateway address range.
geography Match IPv4 gateway address from a specified country.
remote-gw-start-
ip
First IPv4 address in the range. ipv4-
address-any
Not Specified 0.0.0.0
remote-gw-
subnet
IPv4 address and subnet mask. ipv4-
classnet-any
Not Specified 0.0.0.0 0.0.0.0
remote-gw6 IPv6 address of the remote gateway's
external interface.
ipv6-address Not Specified ::
remote-gw6-
country
IPv6 addresses associated to a specific
country.
string Maximum
length: 2
remote-gw6-end-
ip
Last IPv6 address in the range. ipv6-address Not Specified ::
remote-gw6-
match
Set type of IPv6 remote gateway address
matching.
option - any
Option Description
any Match any IPv6 gateway address.
ipprefix Match IPv6 gateway address and prefix.
iprange Match IPv6 gateway address range.
geography Match IPv6 gateway address from a specified country.
remote-gw6-
start-ip
First IPv6 address in the range. ipv6-address Not Specified ::
remote-gw6-
subnet
IPv6 address and prefix. ipv6-network Not Specified ::/0
remotegw-ddns Domain name of remote gateway. For
example, name.ddns.com.
string Maximum
length: 63
rsa-signature-
format
Digital Signature Authentication RSA
signature format.
option - pkcs1
Option Description
pkcs1 RSASSA PKCS#1 v1.5.
pss RSASSA Probabilistic Signature Scheme (PSS).
Parameter Description Type Size Default
rsa-signature-
hash-override
Enable/disable IKEv2 RSA signature
hash algorithm override.
option - disable
Option Description
enable Enable IKEv2 RSA signature hash algorithm override.
disable Disable IKEv2 RSA signature hash algorithm override.
save-password Enable/disable saving XAuth username
and password on VPN clients.
option - disable
Option Description
disable Disable saving XAuth username and password on VPN clients.
enable Enable saving XAuth username and password on VPN clients.
send-cert-chain Enable/disable sending certificate chain. option - enable
Option Description
enable Enable sending certificate chain.
disable Disable sending certificate chain.
signature-hash-
alg
Digital Signature Authentication hash
algorithms.
option - sha2-512
Option Description
sha1 SHA1.
sha2-256 SHA2-256.
sha2-384 SHA2-384.
sha2-512 SHA2-512.
split-include-
service
Split-include services. string Maximum
length: 79
suite-b Use Suite-B. option - disable
Option Description
disable Do not use UI suite.
suite-b-gcm-128 Use Suite-B-GCM-128.
suite-b-gcm-256 Use Suite-B-GCM-256.
transport Set IKE transport protocol. option - udp
Parameter Description Type Size Default
Option Description
udp Use UDP transport for IKE.
udp-fallback-tcp Use UDP transport for IKE, with fallback to TCP transport.
tcp Use TCP transport for IKE.
type Remote gateway type. option - static
Option Description
static Remote VPN gateway has fixed IP address.
dynamic Remote VPN gateway has dynamic IP address.
ddns Remote VPN gateway has dynamic IP address and is a dynamic DNS
client.
unity-support Enable/disable support for Cisco UNITY
Configuration Method extensions.
option - enable
Option Description
disable Disable Cisco Unity Configuration Method Extensions.
enable Enable Cisco Unity Configuration Method Extensions.
usrgrp User group name for dialup peers. string Maximum
length: 35
vni VNI of VXLAN tunnel. integer Minimum
value: 1
Maximum
value:
16777215
0
wizard-type GUI VPN Wizard Type. option - custom
Option Description
custom Custom VPN configuration.
dialup-forticlient Dial Up - FortiClient Windows, Mac and Android.
dialup-ios Dial Up - iPhone / iPad Native IPsec Client.
dialup-android Dial Up - Android Native IPsec Client.
dialup-windows Dial Up - Windows Native IPsec Client.
dialup-cisco Dial Up - Cisco IPsec Client.
static-fortigate Site to Site - FortiGate.
Parameter Description Type Size Default
Option Description
dialup-fortigate Dial Up - FortiGate.
static-cisco Site to Site - Cisco.
dialup-cisco-fw Dialup Up - Cisco Firewall.
simplified-static-
fortigate
Site to Site - FortiGate (SD-WAN).
hub-fortigate-
auto-discovery
Hub role in a Hub-and-Spoke auto-discovery VPN.
spoke-fortigate-
auto-discovery
Spoke role in a Hub-and-Spoke auto-discovery VPN.
xauthtype XAuth type. option - disable
Option Description
disable Disable.
client Enable as client.
pap Enable as server PAP.
chap Enable as server CHAP.
auto Enable as server auto.
- This parameter may not exist in some models.
config ipv4-exclude-range
Parameter Description Type Size Default
end-ip End of IPv4 exclusive range. ipv4-
address
Not Specified 0.0.0.0
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
start-ip Start of IPv4 exclusive range. ipv4-
address
Not Specified 0.0.0.0
config ipv6-exclude-range
Parameter Description Type Size Default
end-ip End of IPv6 exclusive range. ipv6-
address
Not Specified ::
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
start-ip Start of IPv6 exclusive range. ipv6-
address
Not Specified ::

### config vpn ipsec phase1

Configure VPN remote gateway.

#### Syntax

config vpn ipsec phase1
Description: Configure VPN remote gateway.
edit <name>
set acct-verify [enable|disable]
set add-gw-route [enable|disable]
set add-route [disable|enable]
set assign-ip [disable|enable]
set assign-ip-from [range|usrgrp|...]
set authmethod [psk|signature]
set authmethod-remote [psk|signature]
set authpasswd {password}
set authusr {string}
set authusrgrp {string}
set auto-negotiate [enable|disable]
set azure-ad-autoconnect [enable|disable]
set backup-gateway <address1>, <address2>, ...
set banner {var-string}
set cert-id-validation [enable|disable]
set cert-peer-username-strip [disable|enable]
set cert-peer-username-validation [none|othername|...]
set cert-trust-store [local|ems]
set certificate <name1>, <name2>, ...
set childless-ike [enable|disable]
set client-auto-negotiate [disable|enable]
set client-keep-alive [disable|enable]
set client-resume [enable|disable]
set client-resume-interval {integer}
set comments {var-string}
set dev-id {string}
set dev-id-notification [disable|enable]
set dhcp-ra-giaddr {ipv4-address}
set dhcp6-ra-linkaddr {ipv6-address}
set dhgrp {option1}, {option2}, ...
set digital-signature-auth [enable|disable]
set distance {integer}
set dns-mode [manual|auto]
set domain {string}
set dpd [disable|on-idle|...]
set dpd-retrycount {integer}
set dpd-retryinterval {user}
set eap [enable|disable]
set eap-cert-auth [enable|disable]
set eap-exclude-peergrp {string}
set eap-identity [use-id-payload|send-request]
set ems-sn-check [enable|disable]
set enforce-unique-id [disable|keep-new|...]
set esn [require|allow|...]
set exchange-fgt-device-id [enable|disable]
set fallback-tcp-threshold {integer}
set fec-base {integer}
set fec-codec [rs|xor]
set fec-egress [enable|disable]
set fec-health-check {string}
set fec-ingress [enable|disable]
set fec-mapping-profile {string}
set fec-receive-timeout {integer}
set fec-redundant {integer}
set fec-send-timeout {integer}
set fgsp-sync [enable|disable]
set fortinet-esp [enable|disable]
set fragmentation [enable|disable]
set fragmentation-mtu {integer}
set group-authentication [enable|disable]
set group-authentication-secret {password-3}
set ha-sync-esp-seqno [enable|disable]
set idle-timeout [enable|disable]
set idle-timeoutinterval {integer}
set ike-version [1|2]
set inbound-dscp-copy [enable|disable]
set include-local-lan [disable|enable]
set interface {string}
set internal-domain-list <domain-name1>, <domain-name2>, ...
set ip-delay-interval {integer}
set ipv4-dns-server1 {ipv4-address}
set ipv4-dns-server2 {ipv4-address}
set ipv4-dns-server3 {ipv4-address}
set ipv4-end-ip {ipv4-address}
config ipv4-exclude-range
Description: Configuration Method IPv4 exclude ranges.
edit <id>
set end-ip {ipv4-address}
set start-ip {ipv4-address}
next
end
set ipv4-name {string}
set ipv4-netmask {ipv4-netmask}
set ipv4-split-exclude {string}
set ipv4-split-include {string}
set ipv4-start-ip {ipv4-address}
set ipv4-wins-server1 {ipv4-address}
set ipv4-wins-server2 {ipv4-address}
set ipv6-dns-server1 {ipv6-address}
set ipv6-dns-server2 {ipv6-address}
set ipv6-dns-server3 {ipv6-address}
set ipv6-end-ip {ipv6-address}
config ipv6-exclude-range
Description: Configuration method IPv6 exclude ranges.
edit <id>
set end-ip {ipv6-address}
set start-ip {ipv6-address}
next
end
set ipv6-name {string}
set ipv6-prefix {integer}
set ipv6-split-exclude {string}
set ipv6-split-include {string}
set ipv6-start-ip {ipv6-address}
set keepalive {integer}
set keylife {integer}
set kms {string}
set link-cost {integer}
set local-gw {ipv4-address}
set localid {string}
set localid-type [auto|fqdn|...]
set loopback-asymroute [enable|disable]
set mesh-selector-type [disable|subnet|...]
set mode [aggressive|main]
set mode-cfg [disable|enable]
set mode-cfg-allow-client-selector [disable|enable]
set nattraversal [enable|disable|...]
set negotiate-timeout {integer}
set network-id {integer}
set network-overlay [disable|enable]
set npu-offload [enable|disable]
set peer {string}
set peergrp {string}
set peerid {string}
set peertype [any|one|...]
set ppk [disable|allow|...]
set ppk-identity {string}
set ppk-secret {password-3}
set priority {integer}
set proposal {option1}, {option2}, ...
set psksecret {password-3}
set psksecret-remote {password-3}
set qkd [disable|allow|...]
set qkd-profile {string}
set reauth [disable|enable]
set rekey [enable|disable]
set remote-gw {ipv4-address}
set remote-gw-country {string}
set remote-gw-end-ip {ipv4-address-any}
set remote-gw-match [any|ipmask|...]
set remote-gw-start-ip {ipv4-address-any}
set remote-gw-subnet {ipv4-classnet-any}
set remote-gw6-country {string}
set remote-gw6-end-ip {ipv6-address}
set remote-gw6-match [any|ipprefix|...]
set remote-gw6-start-ip {ipv6-address}
set remote-gw6-subnet {ipv6-network}
set remotegw-ddns {string}
set rsa-signature-format [pkcs1|pss]
set rsa-signature-hash-override [enable|disable]
set save-password [disable|enable]
set send-cert-chain [enable|disable]
set signature-hash-alg {option1}, {option2}, ...
set split-include-service {string}
set suite-b [disable|suite-b-gcm-128|...]
set transport [udp|udp-fallback-tcp|...]
set type [static|dynamic|...]
set unity-support [disable|enable]
set usrgrp {string}
set wizard-type [custom|dialup-forticlient|...]
set xauthtype [disable|client|...]
next
end

#### Parameters

config vpn ipsec phase1
Parameter Description Type Size Default
acct-verify Enable/disable verification of RADIUS
accounting record.
option - disable
Option Description
enable Enable verification of RADIUS accounting record.
disable Disable verification of RADIUS accounting record.
add-gw-route Enable/disable automatically add a route to
the remote gateway.
option - disable
Option Description
enable Automatically add a route to the remote gateway.
disable Do not automatically add a route to the remote gateway.
add-route Enable/disable control addition of a route to
peer destination selector.
option - disable
Option Description
disable Do not add a route to destination of peer selector.
enable Add route to destination of peer selector.
assign-ip Enable/disable assignment of IP to IPsec
interface via configuration method.
option - enable
Parameter Description Type Size Default
Option Description
disable Do not assign an IP address to the IPsec interface.
enable Assign an IP address to the IPsec interface.
assign-ip-from Method by which the IP address will be
assigned.
option - range
Option Description
range Assign IP address from locally defined range.
usrgrp Assign IP address via user group.
dhcp Assign IP address via DHCP.
name Assign IP address from firewall address or group.
authmethod Authentication method. option - psk
Option Description
psk PSK authentication method.
signature Signature authentication method.
authmethod-
remote
Authentication method (remote side). option -
Option Description
psk PSK authentication method.
signature Signature authentication method.
authpasswd XAuth password (max 35 characters). password Not
Specified
authusr XAuth user name. string Maximum
length: 64
authusrgrp Authentication user group. string Maximum
length: 35
auto-negotiate Enable/disable automatic initiation of IKE
SA negotiation.
option - enable
Option Description
enable Enable automatic initiation of IKE SA negotiation.
disable Disable automatic initiation of IKE SA negotiation.
Parameter Description Type Size Default
azure-ad-
autoconnect
Enable/disable Azure AD Auto-Connect for
FortiClient.
option - disable
Option Description
enable Enable Azure AD Auto-Connect for FortiClient.
disable Disable Azure AD Auto-Connect for FortiClient.
backup-gateway
<address>
Instruct unity clients about the backup
gateway address(es).
Address of backup gateway.
string Maximum
length: 79
banner Message that unity client should display
after connecting.
var-string Maximum
length: 1024
cert-id-validation Enable/disable cross validation of peer ID
and the identity in the peer's certificate as
specified in RFC 4945.
option - enable
Option Description
enable Enable cross validation of peer ID and the identity in the peer's certificate as
specified in RFC 4945.
disable Disable cross validation of peer ID and the identity in the peer's certificate
as specified in RFC 4945.
cert-peer-
username-strip
Enable/disable domain stripping on
certificate identity.
option - disable
Option Description
disable Disable domain stripping on certificate identity.
enable Enable domain stripping on certificate identity.
cert-peer-
username-
validation
Enable/disable cross validation of peer
username and the identity in the peer's
certificate.
option - none
Option Description
none Disable cross validation of peer username and the identity in the peer's
certificate.
othername Validate principal name in SAN othername.
rfc822name Validate RFC822 email address in SAN.
cn Validate CN in subject.
cert-trust-store CA certificate trust store. option - local
Parameter Description Type Size Default
Option Description
local Use local CA certificate.
ems Use EMS CA certificate.
certificate
<name>
Names of up to 4 signed personal
certificates.
Certificate name.
string Maximum
length: 79
childless-ike Enable/disable childless IKEv2 initiation
(RFC 6023).
option - disable
Option Description
enable Enable childless IKEv2 initiation (RFC 6023).
disable Disable childless IKEv2 initiation (RFC 6023).
client-auto-
negotiate
Enable/disable allowing the VPN client to
bring up the tunnel when there is no traffic.
option - disable
Option Description
disable Disable allowing the VPN client to bring up the tunnel when there is no
traffic.
enable Enable allowing the VPN client to bring up the tunnel when there is no
traffic.
client-keep-alive Enable/disable allowing the VPN client to
keep the tunnel up when there is no traffic.
option - disable
Option Description
disable Disable allowing the VPN client to keep the tunnel up when there is no
traffic.
enable Enable allowing the VPN client to keep the tunnel up when there is no
traffic.
client-resume Enable/disable resumption of offline
FortiClient sessions. When a FortiClient
enabled laptop is closed or enters
sleep/hibernate mode, enabling this feature
allows FortiClient to keep the tunnel during
this period, and allows users to immediately
resume using the IPsec tunnel when the
device wakes up.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable client session resumption.
disable Disable client session resumption.
client-resume-
interval
Maximum time in seconds during which a
VPN client may resume using a tunnel after
a client PC has entered sleep mode or
temporarily lost its network connection.
integer Minimum
value: 120
Maximum
value:
172800
7200
comments Comment. var-string Maximum
length: 255
dev-id Device ID carried by the device ID
notification.
string Maximum
length: 63
dev-id-
notification
Enable/disable device ID notification. option - disable
Option Description
disable Disable device ID notification.
enable Enable device ID notification.
dhcp-ra-giaddr Relay agent gateway IP address to use in
the giaddr field of DHCP requests.
ipv4-address Not
Specified
0.0.0.0
dhcp6-ra-
linkaddr
Relay agent IPv6 link address to use in
DHCP6 requests.
ipv6-address Not
Specified
::
dhgrp DH group. option - 14
Option Description
1 DH Group 1.
2 DH Group 2.
5 DH Group 5.
14 DH Group 14.
15 DH Group 15.
16 DH Group 16.
17 DH Group 17.
18 DH Group 18.
19 DH Group 19.
Parameter Description Type Size Default
Option Description
20 DH Group 20.
21 DH Group 21.
27 DH Group 27.
28 DH Group 28.
29 DH Group 29.
30 DH Group 30.
31 DH Group 31.
32 DH Group 32.
digital-signature-
auth
Enable/disable IKEv2 Digital Signature
Authentication (RFC 7427).
option - disable
Option Description
enable Enable IKEv2 Digital Signature Authentication (RFC 7427).
disable Disable IKEv2 Digital Signature Authentication (RFC 7427).
distance Distance for routes added by IKE. integer Minimum
value: 1
Maximum
value: 255
15
dns-mode DNS server mode. option - manual
Option Description
manual Manually configure DNS servers.
auto Use default DNS servers.
domain Instruct unity clients about the single default
DNS domain.
string Maximum
length: 63
dpd Dead Peer Detection mode. option - on-demand
Option Description
disable Disable Dead Peer Detection.
on-idle Trigger Dead Peer Detection when IPsec is idle.
on-demand Trigger Dead Peer Detection when IPsec traffic is sent but no reply is
received from the peer.
Parameter Description Type Size Default
dpd-retrycount Number of DPD retry attempts. integer Minimum
value: 0
Maximum
value: 10
3
dpd-retryinterval DPD retry interval. user Not
Specified
eap Enable/disable IKEv2 EAP authentication. option - disable
Option Description
enable Enable IKEv2 EAP authentication.
disable Disable IKEv2 EAP authentication.
eap-cert-auth Enable/disable peer certificate
authentication in addition to EAP if peer is a
FortiClient endpoint.
option - disable
Option Description
enable Enable peer certificate authentication in addition to EAP if peer is a
FortiClient endpoint.
disable Disable peer certificate authentication in addition to EAP if peer is a
FortiClient endpoint.
eap-exclude-
peergrp
Peer group excluded from EAP
authentication.
string Maximum
length: 35
eap-identity IKEv2 EAP peer identity type. option - use-id-payload
Option Description
use-id-payload Use IKEv2 IDi payload to resolve peer identity.
send-request Use EAP identity request to resolve peer identity.
ems-sn-check Enable/disable verification of EMS serial
number.
option - disable
Option Description
enable Enable EMS serial number verification.
disable Disable EMS serial number verification.
enforce-unique-
id
Enable/disable peer ID uniqueness check. option - disable
Parameter Description Type Size Default
Option Description
disable Disable peer ID uniqueness enforcement.
keep-new Enforce peer ID uniqueness, keep new connection if collision found.
keep-old Enforce peer ID uniqueness, keep old connection if collision found.
esn * Extended sequence number (ESN)
negotiation.
option - disable
Option Description
require Require extended sequence number.
allow Allow extended sequence number.
disable Disable extended sequence number.
exchange-fgt-
device-id
Enable/disable device identifier exchange
with peer FortiGate units for use of VPN
monitor data by FortiManager.
option - disable
Option Description
enable Enable exchange of FortiGate device identifier.
disable Disable exchange of FortiGate device identifier.
fallback-tcp-
threshold
Timeout in seconds before falling back
IKE/IPsec traffic to tcp.
integer Minimum
value: 1
Maximum
value: 300
15
fec-base Number of base Forward Error Correction
packets.
integer Minimum
value: 1
Maximum
value: 20
10
fec-codec Forward Error Correction
encoding/decoding algorithm.
option - rs
Option Description
rs Reed-Solomon FEC algorithm.
xor XOR FEC algorithm.
fec-egress Enable/disable Forward Error Correction for
egress IPsec traffic.
option - disable
Parameter Description Type Size Default
Option Description
enable Enable Forward Error Correction for egress IPsec traffic.
disable Disable Forward Error Correction for egress IPsec traffic.
fec-health-check SD-WAN health check. string Maximum
length: 35
fec-ingress Enable/disable Forward Error Correction for
ingress IPsec traffic.
option - disable
Option Description
enable Enable Forward Error Correction for ingress IPsec traffic.
disable Disable Forward Error Correction for ingress IPsec traffic.
fec-mapping-
profile
Forward Error Correction (FEC) mapping
profile.
string Maximum
length: 35
fec-receive-
timeout
Timeout in milliseconds before dropping
Forward Error Correction packets.
integer Minimum
value: 1
Maximum
value: 1000
50
fec-redundant Number of redundant Forward Error
Correction packets.
integer Minimum
value: 1
Maximum
value: 5
1
fec-send-timeout Timeout in milliseconds before sending
Forward Error Correction packets.
integer Minimum
value: 1
Maximum
value: 1000
5
fgsp-sync Enable/disable IPsec syncing of tunnels for
FGSP IPsec.
option - disable
Option Description
enable Enable IPsec syncing of tunnels to other cluster members.
disable Disable IPsec syncing of tunnels to other cluster members.
fortinet-esp Enable/disable Fortinet ESP encapsulaton. option - disable
Option Description
enable Enable Fortinet ESP encapsulation.
disable Disable Fortinet ESP encapsulaton.
Parameter Description Type Size Default
fragmentation Enable/disable fragment IKE message on
re-transmission.
option - enable
Option Description
enable Enable intra-IKE fragmentation support on re-transmission.
disable Disable intra-IKE fragmentation support.
fragmentation-
mtu
IKE fragmentation MTU. integer Minimum
value: 500
Maximum
value: 16000
1200
group-
authentication
Enable/disable IKEv2 IDi group
authentication.
option - disable
Option Description
enable Enable IKEv2 IDi group authentication.
disable Disable IKEv2 IDi group authentication.
group-
authentication-
secret
Password for IKEv2 ID group
authentication. ASCII string or hexadecimal
indicated by a leading 0x.
password-3 Not
Specified
ha-sync-esp-
seqno
Enable/disable sequence number jump
ahead for IPsec HA.
option - enable
Option Description
enable Enable HA syncing of ESP sequence numbers.
disable Disable HA syncing of ESP sequence numbers.
idle-timeout Enable/disable IPsec tunnel idle timeout. option - disable
Option Description
enable Enable IPsec tunnel idle timeout.
disable Disable IPsec tunnel idle timeout.
idle-
timeoutinterval
IPsec tunnel idle timeout in minutes. integer Minimum
value: 5
Maximum
value: 43200
15
ike-version IKE protocol version. option - 1
Parameter Description Type Size Default
Option Description
1 Use IKEv1 protocol.
2 Use IKEv2 protocol.
inbound-dscp-
copy
Enable/disable copy the dscp in the ESP
header to the inner IP Header.
option - disable
Option Description
enable Enable copy the dscp in the ESP header to the inner IP Header.
disable Disable copy the dscp in the ESP header to the inner IP Header.
include-local-lan Enable/disable allow local LAN access on
unity clients.
option - disable
Option Description
disable Disable local LAN access on Unity clients.
enable Enable local LAN access on Unity clients.
interface Local physical, aggregate, or VLAN
outgoing interface.
string Maximum
length: 35
internal-domain-
list <domain-
name>
One or more internal domain names in
quotes separated by spaces.
Domain name.
string Maximum
length: 79
ip-delay-interval IP address reuse delay interval in seconds. integer Minimum
value: 0
Maximum
value: 28800
0
ipv4-dns-server1 IPv4 DNS server 1. ipv4-address Not
Specified
0.0.0.0
ipv4-dns-server2 IPv4 DNS server 2. ipv4-address Not
Specified
0.0.0.0
ipv4-dns-server3 IPv4 DNS server 3. ipv4-address Not
Specified
0.0.0.0
ipv4-end-ip End of IPv4 range. ipv4-address Not
Specified
0.0.0.0
ipv4-name IPv4 address name. string Maximum
length: 79
ipv4-netmask IPv4 Netmask. ipv4-
netmask
Not
Specified
255.255.255.255
Parameter Description Type Size Default
ipv4-split-
exclude
IPv4 subnets that should not be sent over
the IPsec tunnel.
string Maximum
length: 79
ipv4-split-include IPv4 split-include subnets. string Maximum
length: 79
ipv4-start-ip Start of IPv4 range. ipv4-address Not
Specified
0.0.0.0
ipv4-wins-
server1
WINS server 1. ipv4-address Not
Specified
0.0.0.0
ipv4-wins-
server2
WINS server 2. ipv4-address Not
Specified
0.0.0.0
ipv6-dns-server1 IPv6 DNS server 1. ipv6-address Not
Specified
::
ipv6-dns-server2 IPv6 DNS server 2. ipv6-address Not
Specified
::
ipv6-dns-server3 IPv6 DNS server 3. ipv6-address Not
Specified
::
ipv6-end-ip End of IPv6 range. ipv6-address Not
Specified
::
ipv6-name IPv6 address name. string Maximum
length: 79
ipv6-prefix IPv6 prefix. integer Minimum
value: 1
Maximum
value: 128
128
ipv6-split-
exclude
IPv6 subnets that should not be sent over
the IPsec tunnel.
string Maximum
length: 79
ipv6-split-include IPv6 split-include subnets. string Maximum
length: 79
ipv6-start-ip Start of IPv6 range. ipv6-address Not
Specified
::
keepalive NAT-T keep alive interval. integer Minimum
value: 5
Maximum
value: 900
10
Parameter Description Type Size Default
keylife Time to wait in seconds before phase 1
encryption key expires.
integer Minimum
value: 120
Maximum
value:
172800
86400
kms Key Management Services server. string Maximum
length: 35
link-cost VPN tunnel underlay link cost. integer Minimum
value: 0
Maximum
value: 255
0
local-gw Local VPN gateway. ipv4-address Not
Specified
0.0.0.0
localid Local ID. string Maximum
length: 63
localid-type Local ID type. option - auto
Option Description
auto Select ID type automatically.
fqdn Use fully qualified domain name.
user-fqdn Use user fully qualified domain name.
keyid Use key-id string.
address Use local IP address.
asn1dn Use ASN.1 distinguished name.
loopback-
asymroute
Enable/disable asymmetric routing for IKE
traffic on loopback interface.
option - enable
Option Description
enable Allow ingress/egress IKE traffic to be routed over different interfaces.
disable Ingress/egress IKE traffic must be routed over the same interface.
mesh-selector-
type
Add selectors containing subsets of the
configuration depending on traffic.
option - disable
Option Description
disable Disable.
subnet Enable addition of matching subnet selector.
host Enable addition of host to host selector.
Parameter Description Type Size Default
mode ID protection mode used to establish a
secure channel.
option - main
Option Description
aggressive Aggressive mode.
main Main mode.
mode-cfg Enable/disable configuration method. option - disable
Option Description
disable Disable Configuration Method.
enable Enable Configuration Method.
mode-cfg-allow-
client-selector
Enable/disable mode-cfg client to use
custom phase2 selectors.
option - disable
Option Description
disable Mode-cfg client to use wildcard selectors.
enable Mode-cfg client to use custom selectors.
name IPsec remote gateway name. string Maximum
length: 35
nattraversal Enable/disable NAT traversal. option - enable
Option Description
enable Enable IPsec NAT traversal.
disable Disable IPsec NAT traversal.
forced Force IPsec NAT traversal on.
negotiate-
timeout
IKE SA negotiation timeout in seconds. integer Minimum
value: 1
Maximum
value: 300
30
network-id VPN gateway network ID. integer Minimum
value: 0
Maximum
value: 255
0
network-overlay Enable/disable network overlays. option - disable
Parameter Description Type Size Default
Option Description
disable Disable network overlays.
enable Enable network overlays.
npu-offload * Enable/disable offloading NPU. option - enable
Option Description
enable Enable NPU offloading.
disable Disable NPU offloading.
peer Accept this peer certificate. string Maximum
length: 35
peergrp Accept this peer certificate group. string Maximum
length: 35
peerid Accept this peer identity. string Maximum
length: 255
peertype Accept this peer type. option - peer
Option Description
any Accept any peer ID.
one Accept this peer ID.
dialup Accept peer ID in dialup group.
peer Accept this peer certificate.
peergrp Accept this peer certificate group.
ppk Enable/disable IKEv2 Postquantum
Preshared Key (PPK).
option - disable
Option Description
disable Disable use of IKEv2 Postquantum Preshared Key (PPK).
allow Allow, but do not require, use of IKEv2 Postquantum Preshared Key (PPK).
require Require use of IKEv2 Postquantum Preshared Key (PPK).
ppk-identity IKEv2 Postquantum Preshared Key
Identity.
string Maximum
length: 35
ppk-secret IKEv2 Postquantum Preshared Key (ASCII
string or hexadecimal encoded with a
leading 0x).
password-3 Not
Specified
Parameter Description Type Size Default
priority Priority for routes added by IKE. integer Minimum
value: 1
Maximum
value: 65535
1
proposal Phase1 proposal. option -
Option Description
des-md5 des-md5
des-sha1 des-sha1
des-sha256 des-sha256
des-sha384 des-sha384
des-sha512 des-sha512
3des-md5 3des-md5
3des-sha1 3des-sha1
3des-sha256 3des-sha256
3des-sha384 3des-sha384
3des-sha512 3des-sha512
aes128-md5 aes128-md5
aes128-sha1 aes128-sha1
aes128-sha256 aes128-sha256
aes128-sha384 aes128-sha384
aes128-sha512 aes128-sha512
aes128gcm-prfsha1 aes128gcm-prfsha1
aes128gcm-prfsha256 aes128gcm-prfsha256
aes128gcm-prfsha384 aes128gcm-prfsha384
aes128gcm-prfsha512 aes128gcm-prfsha512
aes192-md5 aes192-md5
aes192-sha1 aes192-sha1
aes192-sha256 aes192-sha256
aes192-sha384 aes192-sha384
aes192-sha512 aes192-sha512
aes256-md5 aes256-md5
Parameter Description Type Size Default
Option Description
aes256-sha1 aes256-sha1
aes256-sha256 aes256-sha256
aes256-sha384 aes256-sha384
aes256-sha512 aes256-sha512
aes256gcm-prfsha1 aes256gcm-prfsha1
aes256gcm-prfsha256 aes256gcm-prfsha256
aes256gcm-prfsha384 aes256gcm-prfsha384
aes256gcm-prfsha512 aes256gcm-prfsha512
chacha20poly1305-prfsha1 chacha20poly1305-prfsha1
chacha20poly1305-prfsha256 chacha20poly1305-prfsha256
chacha20poly1305-prfsha384 chacha20poly1305-prfsha384
chacha20poly1305-prfsha512 chacha20poly1305-prfsha512
aria128-md5 aria128-md5
aria128-sha1 aria128-sha1
aria128-sha256 aria128-sha256
aria128-sha384 aria128-sha384
aria128-sha512 aria128-sha512
aria192-md5 aria192-md5
aria192-sha1 aria192-sha1
aria192-sha256 aria192-sha256
aria192-sha384 aria192-sha384
aria192-sha512 aria192-sha512
aria256-md5 aria256-md5
aria256-sha1 aria256-sha1
aria256-sha256 aria256-sha256
aria256-sha384 aria256-sha384
aria256-sha512 aria256-sha512
seed-md5 seed-md5
seed-sha1 seed-sha1
Parameter Description Type Size Default
Option Description
seed-sha256 seed-sha256
seed-sha384 seed-sha384
seed-sha512 seed-sha512
psksecret Pre-shared secret for PSK authentication
(ASCII string or hexadecimal encoded with
a leading 0x).
password-3 Not
Specified
psksecret-
remote
Pre-shared secret for remote side PSK
authentication (ASCII string or hexadecimal
encoded with a leading 0x).
password-3 Not
Specified
qkd Enable/disable use of Quantum Key
Distribution (QKD) server.
option - disable
Option Description
disable Disable use of a Quantum Key Distribution (QKD) server.
allow Allow, but do not require, use of a Quantum Key Distribution (QKD) server.
require Require use of a Quantum Key Distribution (QKD) server.
qkd-profile Quantum Key Distribution (QKD) server
profile.
string Maximum
length: 35
reauth Enable/disable re-authentication upon IKE
SA lifetime expiration.
option - disable
Option Description
disable Disable IKE SA re-authentication.
enable Enable IKE SA re-authentication.
rekey Enable/disable phase1 rekey. option - enable
Option Description
enable Enable phase1 rekey.
disable Disable phase1 rekey.
remote-gw Remote VPN gateway. ipv4-address Not
Specified
0.0.0.0
remote-gw-
country
IPv4 addresses associated to a specific
country.
string Maximum
length: 2
Parameter Description Type Size Default
remote-gw-end-
ip
Last IPv4 address in the range. ipv4-
address-any
Not
Specified
0.0.0.0
remote-gw-
match
Set type of IPv4 remote gateway address
matching.
option - any
Option Description
any Match any IPv4 gateway address.
ipmask Match IPv4 gateway address and mask.
iprange Match IPv4 gateway address range.
geography Match IPv4 gateway address from a specified country.
remote-gw-start-
ip
First IPv4 address in the range. ipv4-
address-any
Not
Specified
0.0.0.0
remote-gw-
subnet
IPv4 address and subnet mask. ipv4-
classnet-any
Not
Specified
0.0.0.0 0.0.0.0
remote-gw6-
country
IPv6 addresses associated to a specific
country.
string Maximum
length: 2
remote-gw6-end-
ip
Last IPv6 address in the range. ipv6-address Not
Specified
::
remote-gw6-
match
Set type of IPv6 remote gateway address
matching.
option - any
Option Description
any Match any IPv6 gateway address.
ipprefix Match IPv6 gateway address and prefix.
iprange Match IPv6 gateway address range.
geography Match IPv6 gateway address from a specified country.
remote-gw6-
start-ip
First IPv6 address in the range. ipv6-address Not
Specified
::
remote-gw6-
subnet
IPv6 address and prefix. ipv6-network Not
Specified
::/0
remotegw-ddns Domain name of remote gateway. For
example, name.ddns.com.
string Maximum
length: 63
rsa-signature-
format
Digital Signature Authentication RSA
signature format.
option - pkcs1
Parameter Description Type Size Default
Option Description
pkcs1 RSASSA PKCS#1 v1.5.
pss RSASSA Probabilistic Signature Scheme (PSS).
rsa-signature-
hash-override
Enable/disable IKEv2 RSA signature hash
algorithm override.
option - disable
Option Description
enable Enable IKEv2 RSA signature hash algorithm override.
disable Disable IKEv2 RSA signature hash algorithm override.
save-password Enable/disable saving XAuth username
and password on VPN clients.
option - disable
Option Description
disable Disable saving XAuth username and password on VPN clients.
enable Enable saving XAuth username and password on VPN clients.
send-cert-chain Enable/disable sending certificate chain. option - enable
Option Description
enable Enable sending certificate chain.
disable Disable sending certificate chain.
signature-hash-
alg
Digital Signature Authentication hash
algorithms.
option - sha2-512
Option Description
sha1 SHA1.
sha2-256 SHA2-256.
sha2-384 SHA2-384.
sha2-512 SHA2-512.
split-include-
service
Split-include services. string Maximum
length: 79
suite-b Use Suite-B. option - disable
Option Description
disable Do not use UI suite.
Parameter Description Type Size Default
Option Description
suite-b-gcm-128 Use Suite-B-GCM-128.
suite-b-gcm-256 Use Suite-B-GCM-256.
transport Set IKE transport protocol. option - udp
Option Description
udp Use UDP transport for IKE.
udp-fallback-tcp Use UDP transport for IKE, with fallback to TCP transport.
tcp Use TCP transport for IKE.
type Remote gateway type. option - static
Option Description
static Remote VPN gateway has fixed IP address.
dynamic Remote VPN gateway has dynamic IP address.
ddns Remote VPN gateway has dynamic IP address and is a dynamic DNS
client.
unity-support Enable/disable support for Cisco UNITY
Configuration Method extensions.
option - enable
Option Description
disable Disable Cisco Unity Configuration Method Extensions.
enable Enable Cisco Unity Configuration Method Extensions.
usrgrp User group name for dialup peers. string Maximum
length: 35
wizard-type GUI VPN Wizard Type. option - custom
Option Description
custom Custom VPN configuration.
dialup-forticlient Dial Up - FortiClient Windows, Mac and Android.
dialup-ios Dial Up - iPhone / iPad Native IPsec Client.
dialup-android Dial Up - Android Native IPsec Client.
dialup-windows Dial Up - Windows Native IPsec Client.
dialup-cisco Dial Up - Cisco IPsec Client.
Parameter Description Type Size Default
Option Description
static-fortigate Site to Site - FortiGate.
dialup-fortigate Dial Up - FortiGate.
static-cisco Site to Site - Cisco.
dialup-cisco-fw Dialup Up - Cisco Firewall.
simplified-static-
fortigate
Site to Site - FortiGate (SD-WAN).
hub-fortigate-
auto-discovery
Hub role in a Hub-and-Spoke auto-discovery VPN.
spoke-fortigate-
auto-discovery
Spoke role in a Hub-and-Spoke auto-discovery VPN.
xauthtype XAuth type. option - disable
Option Description
disable Disable.
client Enable as client.
pap Enable as server PAP.
chap Enable as server CHAP.
auto Enable as server auto.
- This parameter may not exist in some models.
config ipv4-exclude-range
Parameter Description Type Size Default
end-ip End of IPv4 exclusive range. ipv4-
address
Not Specified 0.0.0.0
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
start-ip Start of IPv4 exclusive range. ipv4-
address
Not Specified 0.0.0.0
config ipv6-exclude-range
Parameter Description Type Size Default
end-ip End of IPv6 exclusive range. ipv6-
address
Not Specified ::
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
start-ip Start of IPv6 exclusive range. ipv6-
address
Not Specified ::

### config vpn ipsec phase2-interface

Configure VPN autokey tunnel.

#### Syntax

config vpn ipsec phase2-interface
Description: Configure VPN autokey tunnel.
edit <name>
set add-route [phase1|enable|...]
set auto-discovery-forwarder [phase1|enable|...]
set auto-discovery-sender [phase1|enable|...]
set auto-negotiate [enable|disable]
set comments {var-string}
set dhcp-ipsec [enable|disable]
set dhgrp {option1}, {option2}, ...
set diffserv [enable|disable]
set diffservcode {user}
set dst-addr-type [subnet|range|...]
set dst-end-ip {ipv4-address-any}
set dst-end-ip6 {ipv6-address}
set dst-name {string}
set dst-name6 {string}
set dst-port {integer}
set dst-start-ip {ipv4-address-any}
set dst-start-ip6 {ipv6-address}
set dst-subnet {ipv4-classnet-any}
set dst-subnet6 {ipv6-prefix}
set encapsulation [tunnel-mode|transport-mode]
set inbound-dscp-copy [phase1|enable|...]
set initiator-ts-narrow [enable|disable]
set ipv4-df [enable|disable]
set keepalive [enable|disable]
set keylife-type [seconds|kbs|...]
set keylifekbs {integer}
set keylifeseconds {integer}
set l2tp [enable|disable]
set pfs [enable|disable]
set phase1name {string}
set proposal {option1}, {option2}, ...
set protocol {integer}
set replay [enable|disable]
set route-overlap [use-old|use-new|...]
set single-source [enable|disable]
set src-addr-type [subnet|range|...]
set src-end-ip {ipv4-address-any}
set src-end-ip6 {ipv6-address}
set src-name {string}
set src-name6 {string}
set src-port {integer}
set src-start-ip {ipv4-address-any}
set src-start-ip6 {ipv6-address}
set src-subnet {ipv4-classnet-any}
set src-subnet6 {ipv6-prefix}
next
end

#### Parameters

config vpn ipsec phase2-interface
Parameter Description Type Size Default
add-route Enable/disable automatic route addition. option - phase1
Option Description
phase1 Add route according to phase1 add-route setting.
enable Add route for remote proxy ID.
disable Do not add route for remote proxy ID.
auto-discovery-
forwarder
Enable/disable forwarding short-cut messages. option - phase1
Option Description
phase1 Forward short-cut messages according to the phase1 auto-discovery-
forwarder setting.
enable Enable forwarding auto-discovery short-cut messages.
disable Disable forwarding auto-discovery short-cut messages.
auto-discovery-
sender
Enable/disable sending short-cut messages. option - phase1
Option Description
phase1 Send short-cut messages according to the phase1 auto-discovery-sender
setting.
enable Enable sending auto-discovery short-cut messages.
disable Disable sending auto-discovery short-cut messages.
Parameter Description Type Size Default
auto-negotiate Enable/disable IPsec SA auto-negotiation. option - disable
Option Description
enable Enable setting.
disable Disable setting.
comments Comment. var-string Maximum
length: 255
dhcp-ipsec Enable/disable DHCP-IPsec. option - disable
Option Description
enable Enable setting.
disable Disable setting.
dhgrp Phase2 DH group. option - 14
Option Description
1 DH Group 1.
2 DH Group 2.
5 DH Group 5.
14 DH Group 14.
15 DH Group 15.
16 DH Group 16.
17 DH Group 17.
18 DH Group 18.
19 DH Group 19.
20 DH Group 20.
21 DH Group 21.
27 DH Group 27.
28 DH Group 28.
29 DH Group 29.
30 DH Group 30.
31 DH Group 31.
32 DH Group 32.
Parameter Description Type Size Default
diffserv Enable/disable applying DSCP value to the
IPsec tunnel outer IP header.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
diffservcode DSCP value to be applied to the IPsec tunnel
outer IP header.
user Not Specified
dst-addr-type Remote proxy ID type. option - subnet
Option Description
subnet IPv4 subnet.
range IPv4 range.
ip IPv4 IP.
name IPv4 firewall address or group name.
subnet6 IPv6 subnet.
range6 IPv6 range.
ip6 IPv6 IP.
name6 IPv6 firewall address or group name.
dst-end-ip Remote proxy ID IPv4 end. ipv4-
address-any
Not Specified 0.0.0.0
dst-end-ip6 Remote proxy ID IPv6 end. ipv6-
address
Not Specified ::
dst-name Remote proxy ID name. string Maximum
length: 79
dst-name6 Remote proxy ID name. string Maximum
length: 79
dst-port Quick mode destination port. integer Minimum
value: 0
Maximum
value: 65535
0
dst-start-ip Remote proxy ID IPv4 start. ipv4-
address-any
Not Specified 0.0.0.0
dst-start-ip6 Remote proxy ID IPv6 start. ipv6-
address
Not Specified ::
Parameter Description Type Size Default
dst-subnet Remote proxy ID IPv4 subnet. ipv4-
classnet-any
Not Specified 0.0.0.0
0.0.0.0
dst-subnet6 Remote proxy ID IPv6 subnet. ipv6-prefix Not Specified ::/0
encapsulation ESP encapsulation mode. option - tunnel-mode
Option Description
tunnel-mode Use tunnel mode encapsulation.
transport-mode Use transport mode encapsulation.
inbound-dscp-
copy
Enable/disable copying of the DSCP in the ESP
header to the inner IP header.
option - phase1
Option Description
phase1 copy the DCSP in the ESP header to the inner IP Header according to the
phase1 inbound_dscp_copy setting.
enable Enable copying of the DSCP in the ESP header to the inner IP header.
disable Disable copying of the DSCP in the ESP header to the inner IP header.
initiator-ts-
narrow
Enable/disable traffic selector narrowing for
IKEv2 initiator.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
ipv4-df Enable/disable setting and resetting of IPv4
'Don't Fragment' bit.
option - disable
Option Description
enable Set IPv4 DF the same as original packet.
disable Reset IPv4 DF.
keepalive Enable/disable keep alive. option - disable
Option Description
enable Enable setting.
disable Disable setting.
keylife-type Keylife type. option - seconds
Parameter Description Type Size Default
Option Description
seconds Key life in seconds.
kbs Key life in kilobytes.
both Key life both.
keylifekbs Phase2 key life in number of kilobytes of traffic. integer Minimum
value: 5120
Maximum
value:
4294967295
5120
keylifeseconds Phase2 key life in time in seconds. integer Minimum
value: 120
Maximum
value: 172800
43200
l2tp Enable/disable L2TP over IPsec. option - disable
Option Description
enable Enable L2TP over IPsec.
disable Disable L2TP over IPsec.
name IPsec tunnel name. string Maximum
length: 35
pfs Enable/disable PFS feature. option - enable
Option Description
enable Enable setting.
disable Disable setting.
phase1name Phase 1 determines the options required for
phase 2.
string Maximum
length: 15
proposal Phase2 proposal. option -
Option Description
null-md5 null-md5
null-sha1 null-sha1
null-sha256 null-sha256
null-sha384 null-sha384
Parameter Description Type Size Default
Option Description
null-sha512 null-sha512
des-null des-null
des-md5 des-md5
des-sha1 des-sha1
des-sha256 des-sha256
des-sha384 des-sha384
des-sha512 des-sha512
3des-null 3des-null
3des-md5 3des-md5
3des-sha1 3des-sha1
3des-sha256 3des-sha256
3des-sha384 3des-sha384
3des-sha512 3des-sha512
aes128-null aes128-null
aes128-md5 aes128-md5
aes128-sha1 aes128-sha1
aes128-sha256 aes128-sha256
aes128-sha384 aes128-sha384
aes128-sha512 aes128-sha512
aes128gcm aes128gcm
aes192-null aes192-null
aes192-md5 aes192-md5
aes192-sha1 aes192-sha1
aes192-sha256 aes192-sha256
aes192-sha384 aes192-sha384
aes192-sha512 aes192-sha512
aes256-null aes256-null
aes256-md5 aes256-md5
aes256-sha1 aes256-sha1
Parameter Description Type Size Default
Option Description
aes256-sha256 aes256-sha256
aes256-sha384 aes256-sha384
aes256-sha512 aes256-sha512
aes256gcm aes256gcm
chacha20poly1305 chacha20poly1305
aria128-null aria128-null
aria128-md5 aria128-md5
aria128-sha1 aria128-sha1
aria128-sha256 aria128-sha256
aria128-sha384 aria128-sha384
aria128-sha512 aria128-sha512
aria192-null aria192-null
aria192-md5 aria192-md5
aria192-sha1 aria192-sha1
aria192-sha256 aria192-sha256
aria192-sha384 aria192-sha384
aria192-sha512 aria192-sha512
aria256-null aria256-null
aria256-md5 aria256-md5
aria256-sha1 aria256-sha1
aria256-sha256 aria256-sha256
aria256-sha384 aria256-sha384
aria256-sha512 aria256-sha512
seed-null seed-null
seed-md5 seed-md5
seed-sha1 seed-sha1
seed-sha256 seed-sha256
seed-sha384 seed-sha384
seed-sha512 seed-sha512
Parameter Description Type Size Default
protocol Quick mode protocol selector. integer Minimum
value: 0
Maximum
value: 255
0
replay Enable/disable replay detection. option - enable
Option Description
enable Enable setting.
disable Disable setting.
route-overlap Action for overlapping routes. option - use-new
Option Description
use-old Use the old route and do not add the new route.
use-new Delete the old route and add the new route.
allow Allow overlapping routes.
single-source Enable/disable single source IP restriction. option - disable
Option Description
enable Only single source IP will be accepted.
disable Source IP range will be accepted.
src-addr-type Local proxy ID type. option - subnet
Option Description
subnet IPv4 subnet.
range IPv4 range.
ip IPv4 IP.
name IPv4 firewall address or group name.
subnet6 IPv6 subnet.
range6 IPv6 range.
ip6 IPv6 IP.
name6 IPv6 firewall address or group name.
src-end-ip Local proxy ID end. ipv4-
address-any
Not Specified 0.0.0.0
Parameter Description Type Size Default
src-end-ip6 Local proxy ID IPv6 end. ipv6-
address
Not Specified ::
src-name Local proxy ID name. string Maximum
length: 79
src-name6 Local proxy ID name. string Maximum
length: 79
src-port Quick mode source port. integer Minimum
value: 0
Maximum
value: 65535
0
src-start-ip Local proxy ID start. ipv4-
address-any
Not Specified 0.0.0.0
src-start-ip6 Local proxy ID IPv6 start. ipv6-
address
Not Specified ::
src-subnet Local proxy ID subnet. ipv4-
classnet-any
Not Specified 0.0.0.0
0.0.0.0
src-subnet6 Local proxy ID IPv6 subnet. ipv6-prefix Not Specified ::/0

### config vpn ipsec phase2

Configure VPN autokey tunnel.

#### Syntax

config vpn ipsec phase2
Description: Configure VPN autokey tunnel.
edit <name>
set add-route [phase1|enable|...]
set auto-negotiate [enable|disable]
set comments {var-string}
set dhcp-ipsec [enable|disable]
set dhgrp {option1}, {option2}, ...
set diffserv [enable|disable]
set diffservcode {user}
set dst-addr-type [subnet|range|...]
set dst-end-ip {ipv4-address-any}
set dst-end-ip6 {ipv6-address}
set dst-name {string}
set dst-name6 {string}
set dst-port {integer}
set dst-start-ip {ipv4-address-any}
set dst-start-ip6 {ipv6-address}
set dst-subnet {ipv4-classnet-any}
set dst-subnet6 {ipv6-prefix}
set encapsulation [tunnel-mode|transport-mode]
set inbound-dscp-copy [phase1|enable|...]
set initiator-ts-narrow [enable|disable]
set ipv4-df [enable|disable]
set keepalive [enable|disable]
set keylife-type [seconds|kbs|...]
set keylifekbs {integer}
set keylifeseconds {integer}
set l2tp [enable|disable]
set pfs [enable|disable]
set phase1name {string}
set proposal {option1}, {option2}, ...
set protocol {integer}
set replay [enable|disable]
set route-overlap [use-old|use-new|...]
set selector-match [exact|subset|...]
set single-source [enable|disable]
set src-addr-type [subnet|range|...]
set src-end-ip {ipv4-address-any}
set src-end-ip6 {ipv6-address}
set src-name {string}
set src-name6 {string}
set src-port {integer}
set src-start-ip {ipv4-address-any}
set src-start-ip6 {ipv6-address}
set src-subnet {ipv4-classnet-any}
set src-subnet6 {ipv6-prefix}
set use-natip [enable|disable]
next
end

#### Parameters

config vpn ipsec phase2
Parameter Description Type Size Default
add-route Enable/disable automatic route addition. option - phase1
Option Description
phase1 Add route according to phase1 add-route setting.
enable Add route for remote proxy ID.
disable Do not add route for remote proxy ID.
auto-negotiate Enable/disable IPsec SA auto-negotiation. option - disable
Option Description
enable Enable setting.
disable Disable setting.
comments Comment. var-string Maximum
length: 255
dhcp-ipsec Enable/disable DHCP-IPsec. option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
dhgrp Phase2 DH group. option - 14
Option Description
1 DH Group 1.
2 DH Group 2.
5 DH Group 5.
14 DH Group 14.
15 DH Group 15.
16 DH Group 16.
17 DH Group 17.
18 DH Group 18.
19 DH Group 19.
20 DH Group 20.
21 DH Group 21.
27 DH Group 27.
28 DH Group 28.
29 DH Group 29.
30 DH Group 30.
31 DH Group 31.
32 DH Group 32.
diffserv Enable/disable applying DSCP value to the
IPsec tunnel outer IP header.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
diffservcode DSCP value to be applied to the IPsec tunnel
outer IP header.
user Not Specified
dst-addr-type Remote proxy ID type. option - subnet
Parameter Description Type Size Default
Option Description
subnet IPv4 subnet.
range IPv4 range.
ip IPv4 IP.
name IPv4 firewall address or group name.
dst-end-ip Remote proxy ID IPv4 end. ipv4-
address-any
Not Specified 0.0.0.0
dst-end-ip6 Remote proxy ID IPv6 end. ipv6-
address
Not Specified ::
dst-name Remote proxy ID name. string Maximum
length: 79
dst-name6 Remote proxy ID name. string Maximum
length: 79
dst-port Quick mode destination port. integer Minimum
value: 0
Maximum
value: 65535
0
dst-start-ip Remote proxy ID IPv4 start. ipv4-
address-any
Not Specified 0.0.0.0
dst-start-ip6 Remote proxy ID IPv6 start. ipv6-
address
Not Specified ::
dst-subnet Remote proxy ID IPv4 subnet. ipv4-
classnet-any
Not Specified 0.0.0.0
0.0.0.0
dst-subnet6 Remote proxy ID IPv6 subnet. ipv6-prefix Not Specified ::/0
encapsulation ESP encapsulation mode. option - tunnel-mode
Option Description
tunnel-mode Use tunnel mode encapsulation.
transport-mode Use transport mode encapsulation.
inbound-dscp-
copy
Enable/disable copying of the DSCP in the ESP
header to the inner IP header.
option - phase1
Option Description
phase1 copy the DCSP in the ESP header to the inner IP Header according to the
phase1 inbound_dscp_copy setting.
Parameter Description Type Size Default
Option Description
enable Enable copying of the DSCP in the ESP header to the inner IP header.
disable Disable copying of the DSCP in the ESP header to the inner IP header.
initiator-ts-
narrow
Enable/disable traffic selector narrowing for
IKEv2 initiator.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
ipv4-df Enable/disable setting and resetting of IPv4
'Don't Fragment' bit.
option - disable
Option Description
enable Set IPv4 DF the same as original packet.
disable Reset IPv4 DF.
keepalive Enable/disable keep alive. option - disable
Option Description
enable Enable setting.
disable Disable setting.
keylife-type Keylife type. option - seconds
Option Description
seconds Key life in seconds.
kbs Key life in kilobytes.
both Key life both.
keylifekbs Phase2 key life in number of kilobytes of traffic. integer Minimum
value: 5120
Maximum
value:
4294967295
5120
keylifeseconds Phase2 key life in time in seconds. integer Minimum
value: 120
Maximum
value: 172800
43200
Parameter Description Type Size Default
l2tp Enable/disable L2TP over IPsec. option - disable
Option Description
enable Enable L2TP over IPsec.
disable Disable L2TP over IPsec.
name IPsec tunnel name. string Maximum
length: 35
pfs Enable/disable PFS feature. option - enable
Option Description
enable Enable setting.
disable Disable setting.
phase1name Phase 1 determines the options required for
phase 2.
string Maximum
length: 35
proposal Phase2 proposal. option -
Option Description
null-md5 null-md5
null-sha1 null-sha1
null-sha256 null-sha256
null-sha384 null-sha384
null-sha512 null-sha512
des-null des-null
des-md5 des-md5
des-sha1 des-sha1
des-sha256 des-sha256
des-sha384 des-sha384
des-sha512 des-sha512
3des-null 3des-null
3des-md5 3des-md5
3des-sha1 3des-sha1
3des-sha256 3des-sha256
Parameter Description Type Size Default
Option Description
3des-sha384 3des-sha384
3des-sha512 3des-sha512
aes128-null aes128-null
aes128-md5 aes128-md5
aes128-sha1 aes128-sha1
aes128-sha256 aes128-sha256
aes128-sha384 aes128-sha384
aes128-sha512 aes128-sha512
aes128gcm aes128gcm
aes192-null aes192-null
aes192-md5 aes192-md5
aes192-sha1 aes192-sha1
aes192-sha256 aes192-sha256
aes192-sha384 aes192-sha384
aes192-sha512 aes192-sha512
aes256-null aes256-null
aes256-md5 aes256-md5
aes256-sha1 aes256-sha1
aes256-sha256 aes256-sha256
aes256-sha384 aes256-sha384
aes256-sha512 aes256-sha512
aes256gcm aes256gcm
chacha20poly1305 chacha20poly1305
aria128-null aria128-null
aria128-md5 aria128-md5
aria128-sha1 aria128-sha1
aria128-sha256 aria128-sha256
aria128-sha384 aria128-sha384
aria128-sha512 aria128-sha512
Parameter Description Type Size Default
Option Description
aria192-null aria192-null
aria192-md5 aria192-md5
aria192-sha1 aria192-sha1
aria192-sha256 aria192-sha256
aria192-sha384 aria192-sha384
aria192-sha512 aria192-sha512
aria256-null aria256-null
aria256-md5 aria256-md5
aria256-sha1 aria256-sha1
aria256-sha256 aria256-sha256
aria256-sha384 aria256-sha384
aria256-sha512 aria256-sha512
seed-null seed-null
seed-md5 seed-md5
seed-sha1 seed-sha1
seed-sha256 seed-sha256
seed-sha384 seed-sha384
seed-sha512 seed-sha512
protocol Quick mode protocol selector. integer Minimum
value: 0
Maximum
value: 255
0
replay Enable/disable replay detection. option - enable
Option Description
enable Enable setting.
disable Disable setting.
route-overlap Action for overlapping routes. option - use-new
Option Description
use-old Use the old route and do not add the new route.
Parameter Description Type Size Default
Option Description
use-new Delete the old route and add the new route.
allow Allow overlapping routes.
selector-match Match type to use when comparing selectors. option - auto
Option Description
exact Match selectors exactly.
subset Match selectors by subset.
auto Use subset or exact match depending on selector address type.
single-source Enable/disable single source IP restriction. option - disable
Option Description
enable Only single source IP will be accepted.
disable Source IP range will be accepted.
src-addr-type Local proxy ID type. option - subnet
Option Description
subnet IPv4 subnet.
range IPv4 range.
ip IPv4 IP.
name IPv4 firewall address or group name.
src-end-ip Local proxy ID end. ipv4-
address-any
Not Specified 0.0.0.0
src-end-ip6 Local proxy ID IPv6 end. ipv6-
address
Not Specified ::
src-name Local proxy ID name. string Maximum
length: 79
src-name6 Local proxy ID name. string Maximum
length: 79
src-port Quick mode source port. integer Minimum
value: 0
Maximum
value: 65535
0
Parameter Description Type Size Default
src-start-ip Local proxy ID start. ipv4-
address-any
Not Specified 0.0.0.0
src-start-ip6 Local proxy ID IPv6 start. ipv6-
address
Not Specified ::
src-subnet Local proxy ID subnet. ipv4-
classnet-any
Not Specified 0.0.0.0
0.0.0.0
src-subnet6 Local proxy ID IPv6 subnet. ipv6-prefix Not Specified ::/0
use-natip Enable to use the FortiGate public IP as the
source selector when outbound NAT is used.
option - enable
Option Description
enable Replace source selector with interface IP when using outbound NAT.
disable Do not modify source selector when using outbound NAT.

### config vpn kmip-server

KMIP server entry configuration.

#### Syntax

config vpn kmip-server
Description: KMIP server entry configuration.
edit <name>
set interface {string}
set interface-select-method [auto|sdwan|...]
set password {password}
set server-identity-check [enable|disable]
config server-list
Description: KMIP server list.
edit <id>
set cert {string}
set port {integer}
set server {string}
set status [enable|disable]
next
end
set source-ip {string}
set ssl-min-proto-version [default|SSLv3|...]
set username {string}
next
end

---

## config_vpn_ssl.md

# config vpn ssl

> Source: `config vpn ssl.pdf`
> FortiOS 7.4.6 CLI reference extraction. Repeated PDF page headers and footers were omitted.
> Page-boundary carry-over from adjacent CLI sections is retained when it appears in the uploaded PDF.

set server {string}
next
end

#### Parameters

config vpn qkd
Parameter Description Type Size Default
certificate
<name>
Names of up to 4 certificates to offer to the KME.
Certificate name.
string Maximum
length: 79
comment Comment. var-string Maximum
length: 255
id Quantum Key Distribution ID assigned by the KME. string Maximum
length: 291
name Quantum Key Distribution configuration name. string Maximum
length: 35
peer Authenticate Quantum Key Device's certificate with the
peer/peergrp.
string Maximum
length: 35
port Port to connect to on the KME. integer Minimum
value: 1
Maximum
value:
65535
0
server IPv4, IPv6 or DNS address of the KME. string Maximum
length: 63

### config vpn ssl client

Client.

#### Syntax

config vpn ssl client
Description: Client.
edit <name>
set certificate {string}
set class-id {integer}
set comment {var-string}
set distance {integer}
set interface {string}
set ipv4-subnets {string}
set ipv6-subnets {string}
set peer {string}
set port {integer}
set priority {integer}
set psk {password-3}
set realm {string}
set server {string}
set source-ip {string}
set status [enable|disable]
set user {string}
next
end

#### Parameters

config vpn ssl client
Parameter Description Type Size Default
certificate Certificate to offer to SSL-VPN server if it requests
one.
string Maximum
length: 35
class-id Traffic class ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
comment Comment. var-string Maximum
length: 255
distance Distance for routes added by SSL-VPN. integer Minimum
value: 1
Maximum
value: 255
10
interface SSL interface to send/receive traffic over. string Maximum
length: 15
ipv4-subnets IPv4 subnets that the client is protecting. string Maximum
length: 79
ipv6-subnets IPv6 subnets that the client is protecting. string Maximum
length: 79
name SSL-VPN tunnel name. string Maximum
length: 35
peer Authenticate peer's certificate with the peer/peergrp. string Maximum
length: 35
port SSL-VPN server port. integer Minimum
value: 1
Maximum
value: 65535
443
priority Priority for routes added by SSL-VPN. integer Minimum
value: 1
Maximum
value: 65535
1
psk Pre-shared secret to authenticate with the server
(ASCII string or hexadecimal encoded with a leading
0x).
password-3 Not Specified
Parameter Description Type Size Default
realm Realm name configured on SSL-VPN server. string Maximum
length: 35
server IPv4, IPv6 or DNS address of the SSL-VPN server. string Maximum
length: 63
source-ip IPv4 or IPv6 address to use as a source for the SSL-
VPN connection to the server.
string Maximum
length: 63
status Enable/disable this SSL-VPN client configuration. option - enable
Option Description
enable Enable the SSL-VPN configuration.
disable Disable the SSL-VPN configuration.
user Username to offer to the peer to authenticate the
client.
string Maximum
length: 35

### config vpn ssl settings

Configure SSL-VPN.

#### Syntax

config vpn ssl settings
Description: Configure SSL-VPN.
set algorithm [high|medium|...]
set auth-session-check-source-ip [enable|disable]
set auth-timeout {integer}
config authentication-rule
Description: Authentication rule for SSL-VPN.
edit <id>
set auth [any|local|...]
set cipher [any|high|...]
set client-cert [enable|disable]
set groups <name1>, <name2>, ...
set portal {string}
set realm {string}
set source-address <name1>, <name2>, ...
set source-address-negate [enable|disable]
set source-address6 <name1>, <name2>, ...
set source-address6-negate [enable|disable]
set source-interface <name1>, <name2>, ...
set user-peer {string}
set users <name1>, <name2>, ...
next
end
set auto-tunnel-static-route [enable|disable]
set banned-cipher {option1}, {option2}, ...
set browser-language-detection [enable|disable]
set check-referer [enable|disable]
set ciphersuite {option1}, {option2}, ...
set client-sigalgs [no-rsa-pss|all]
set default-portal {string}
set deflate-compression-level {integer}
set deflate-min-data-size {integer}
set dns-server1 {ipv4-address}
set dns-server2 {ipv4-address}
set dns-suffix {var-string}
set dtls-heartbeat-fail-count {integer}
set dtls-heartbeat-idle-timeout {integer}
set dtls-heartbeat-interval {integer}
set dtls-hello-timeout {integer}
set dtls-max-proto-ver [dtls1-0|dtls1-2]
set dtls-min-proto-ver [dtls1-0|dtls1-2]
set dtls-tunnel [enable|disable]
set dual-stack-mode [enable|disable]
set encode-2f-sequence [enable|disable]
set encrypt-and-store-password [enable|disable]
set force-two-factor-auth [enable|disable]
set header-x-forwarded-for [pass|add|...]
set hsts-include-subdomains [enable|disable]
set http-compression [enable|disable]
set http-only-cookie [enable|disable]
set http-request-body-timeout {integer}
set http-request-header-timeout {integer}
set https-redirect [enable|disable]
set idle-timeout {integer}
set ipv6-dns-server1 {ipv6-address}
set ipv6-dns-server2 {ipv6-address}
set ipv6-wins-server1 {ipv6-address}
set ipv6-wins-server2 {ipv6-address}
set login-attempt-limit {integer}
set login-block-time {integer}
set login-timeout {integer}
set port {integer}
set port-precedence [enable|disable]
set reqclientcert [enable|disable]
set saml-redirect-port {integer}
set server-hostname {string}
set servercert {string}
set source-address <name1>, <name2>, ...
set source-address-negate [enable|disable]
set source-address6 <name1>, <name2>, ...
set source-address6-negate [enable|disable]
set source-interface <name1>, <name2>, ...
set ssl-client-renegotiation [disable|enable]
set ssl-insert-empty-fragment [enable|disable]
set ssl-max-proto-ver [tls1-0|tls1-1|...]
set ssl-min-proto-ver [tls1-0|tls1-1|...]
set status [enable|disable]
set transform-backward-slashes [enable|disable]
set tunnel-addr-assigned-method [first-available|round-robin]
set tunnel-connect-without-reauth [enable|disable]
set tunnel-ip-pools <name1>, <name2>, ...
set tunnel-ipv6-pools <name1>, <name2>, ...
set tunnel-user-session-timeout {integer}
set unsafe-legacy-renegotiation [enable|disable]
set url-obscuration [enable|disable]
set user-peer {string}
set wins-server1 {ipv4-address}
set wins-server2 {ipv4-address}
set x-content-type-options [enable|disable]
set ztna-trusted-client [enable|disable]
end

#### Parameters

config vpn ssl settings
Parameter Description Type Size Default
algorithm Force the SSL-VPN security level. High allows
only high. Medium allows medium and high. Low
allows any.
option - high
Option Description
high High algorithms.
medium High and medium algorithms.
default default
low All algorithms.
auth-session-
check-source-ip
Enable/disable checking of source IP for
authentication session.
option - enable
Option Description
enable Enable checking of source IP for authentication session.
disable Disable checking of source IP for authentication session.
auth-timeout SSL-VPN authentication timeout. integer Minimum
value: 0
Maximum
value: 259200
28800
auto-tunnel-
static-route
Enable/disable to auto-create static routes for
the SSL-VPN tunnel IP addresses.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
banned-cipher Select one or more cipher technologies that
cannot be used in SSL-VPN negotiations. Only
applies to TLS 1.2 and below.
option - SHA1 SHA256
SHA384
Parameter Description Type Size Default
Option Description
RSA Ban the use of cipher suites using RSA key.
DHE Ban the use of cipher suites using authenticated ephemeral DH key
agreement.
ECDHE Ban the use of cipher suites using authenticated ephemeral ECDH key
agreement.
DSS Ban the use of cipher suites using DSS authentication.
ECDSA Ban the use of cipher suites using ECDSA authentication.
AES Ban the use of cipher suites using either 128 or 256 bit AES.
AESGCM Ban the use of cipher suites AES in Galois Counter Mode (GCM).
CAMELLIA Ban the use of cipher suites using either 128 or 256 bit CAMELLIA.
3DES Ban the use of cipher suites using triple DES
SHA1 Ban the use of cipher suites using HMAC-SHA1.
SHA256 Ban the use of cipher suites using HMAC-SHA256.
SHA384 Ban the use of cipher suites using HMAC-SHA384.
STATIC Ban the use of cipher suites using static keys.
CHACHA20 Ban the use of cipher suites using ChaCha20.
ARIA Ban the use of cipher suites using ARIA.
AESCCM Ban the use of cipher suites using AESCCM.
browser-
language-
detection
Enable/disable overriding the configured system
language based on the preferred language of
the browser.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
check-referer Enable/disable verification of referer field in
HTTP request header.
option - disable
Option Description
enable Enable verification of referer field in HTTP request header.
disable Disable verification of referer field in HTTP request header.
Parameter Description Type Size Default
ciphersuite Select one or more TLS 1.3 ciphersuites to
enable. Does not affect ciphers in TLS 1.2 and
below. At least one must be enabled. To disable
all, set ssl-max-proto-ver to tls1-2 or below.
option - TLS-AES-128-
GCM-SHA256
TLS-AES-256-
GCM-SHA384
TLS-
CHACHA20-
POLY1305-
SHA256
Option Description
TLS-AES-128-
GCM-SHA256
Enable TLS-AES-128-GCM-SHA256 in TLS 1.3.
TLS-AES-256-
GCM-SHA384
Enable TLS-AES-256-GCM-SHA384 in TLS 1.3.
TLS-
CHACHA20-
POLY1305-
SHA256
Enable TLS-CHACHA20-POLY1305-SHA256 in TLS 1.3.
TLS-AES-128-
CCM-SHA256
Enable TLS-AES-128-CCM-SHA256 in TLS 1.3.
TLS-AES-128-
CCM-8-SHA256
Enable TLS-AES-128-CCM-8-SHA256 in TLS 1.3.
client-sigalgs Set signature algorithms related to client
authentication. Affects TLS version <= 1.2 only.
option - all
Option Description
no-rsa-pss Disable RSA-PSS signature algorithms for client authentication.
all Enable all supported signature algorithms for client authentication.
default-portal Default SSL-VPN portal. string Maximum
length: 35
deflate-
compression-
level
Compression level (0~9). integer Minimum
value: 0
Maximum
value: 9
6
deflate-min-
data-size
Minimum amount of data that triggers
compression.
integer Minimum
value: 200
Maximum
value: 65535
300
Parameter Description Type Size Default
dns-server1 DNS server 1. ipv4-
address
Not Specified 0.0.0.0
dns-server2 DNS server 2. ipv4-
address
Not Specified 0.0.0.0
dns-suffix DNS suffix used for SSL-VPN clients. var-string Maximum
length: 253
dtls-heartbeat-
fail-count
Number of missing heartbeats before the
connection is considered dropped.
integer Minimum
value: 3
Maximum
value: 10
3
dtls-heartbeat-
idle-timeout
Idle timeout before DTLS heartbeat is sent. integer Minimum
value: 3
Maximum
value: 10
3
dtls-heartbeat-
interval
Interval between DTLS heartbeat. integer Minimum
value: 3
Maximum
value: 10
3
dtls-hello-
timeout
SSLVPN maximum DTLS hello timeout. integer Minimum
value: 10
Maximum
value: 60
10
dtls-max-proto-
ver
DTLS maximum protocol version. option - dtls1-2
Option Description
dtls1-0 DTLS version 1.0.
dtls1-2 DTLS version 1.2.
dtls-min-proto-
ver
DTLS minimum protocol version. option - dtls1-0
Option Description
dtls1-0 DTLS version 1.0.
dtls1-2 DTLS version 1.2.
dtls-tunnel Enable/disable DTLS to prevent eavesdropping,
tampering, or message forgery.
option - enable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
dual-stack-
mode
Tunnel mode: enable parallel IPv4 and IPv6
tunnel. Web mode: support IPv4 and IPv6
bookmarks in the portal.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
encode-2f-
sequence
Encode \2F sequence to forward slash in URLs. option - disable
Option Description
enable Enable setting.
disable Disable setting.
encrypt-and-
store-password
Encrypt and store user passwords for SSL-VPN
web sessions.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
force-two-
factor-auth
Enable/disable only PKI users with two-factor
authentication for SSL-VPNs.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
header-x-
forwarded-for
Forward the same, add, or remove HTTP
header.
option - add
Option Description
pass Forward the same HTTP header.
add Add the HTTP header.
remove Remove the HTTP header.
Parameter Description Type Size Default
hsts-include-
subdomains
Add HSTS includeSubDomains response
header.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
http-
compression
Enable/disable to allow HTTP compression over
SSL-VPN tunnels.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
http-only-cookie Enable/disable SSL-VPN support for HttpOnly
cookies.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
http-request-
body-timeout
SSL-VPN session is disconnected if an HTTP
request body is not received within this time.
integer Minimum
value: 0
Maximum
value:
4294967295
30
http-request-
header-timeout
SSL-VPN session is disconnected if an HTTP
request header is not received within this time.
integer Minimum
value: 0
Maximum
value:
4294967295
20
https-redirect Enable/disable redirect of port 80 to SSL-VPN
port.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
idle-timeout SSL-VPN disconnects if idle for specified time in
seconds.
integer Minimum
value: 0
Maximum
value: 259200
300
Parameter Description Type Size Default
ipv6-dns-
server1
IPv6 DNS server 1. ipv6-
address
Not Specified ::
ipv6-dns-
server2
IPv6 DNS server 2. ipv6-
address
Not Specified ::
ipv6-wins-
server1
IPv6 WINS server 1. ipv6-
address
Not Specified ::
ipv6-wins-
server2
IPv6 WINS server 2. ipv6-
address
Not Specified ::
login-attempt-
limit
SSL-VPN maximum login attempt times before
block.
integer Minimum
value: 0
Maximum
value:
4294967295
2
login-block-time Time for which a user is blocked from logging in
after too many failed login attempts.
integer Minimum
value: 0
Maximum
value:
4294967295
60
login-timeout SSLVPN maximum login timeout. integer Minimum
value: 10
Maximum
value: 180
30
port SSL-VPN access port. integer Minimum
value: 1
Maximum
value: 65535
10443
port-
precedence
Enable/disable, Enable means that if SSL-VPN
connections are allowed on an interface admin
GUI connections are blocked on that interface.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
reqclientcert Enable/disable to require client certificates for all
SSL-VPN users.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
saml-redirect-
port
SAML local redirect port in the machine running
FortiClient. 0 is to disable redirection on FGT
side.
integer Minimum
value: 0
Maximum
value: 65535
8020
server-
hostname
Server hostname for HTTPS. When set, will be
used for SSL VPN web proxy host header for
any redirection.
string Maximum
length: 255
servercert Name of the server certificate to be used for
SSL-VPNs.
string Maximum
length: 35
source-address
<name>
Source address of incoming traffic.
Address name.
string Maximum
length: 79
source-
address-negate
Enable/disable negated source address match. option - disable
Option Description
enable Enable setting.
disable Disable setting.
source-
address6
<name>
IPv6 source address of incoming traffic.
IPv6 address name.
string Maximum
length: 79
source-
address6-
negate
Enable/disable negated source IPv6 address
match.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
source-
interface
<name>
SSL-VPN source interface of incoming traffic.
Interface name.
string Maximum
length: 35
ssl-client-
renegotiation
Enable/disable to allow client renegotiation by
the server if the tunnel goes down.
option - disable
Option Description
disable Abort any SSL connection that attempts to renegotiate.
enable Allow a SSL client to renegotiate.
Parameter Description Type Size Default
ssl-insert-
empty-fragment
Enable/disable insertion of empty fragment. option - enable
Option Description
enable Enable setting.
disable Disable setting.
ssl-max-proto-
ver
SSL maximum protocol version. option - tls1-3
Option Description
tls1-0 TLS version 1.0.
tls1-1 TLS version 1.1.
tls1-2 TLS version 1.2.
tls1-3 TLS version 1.3.
ssl-min-proto-
ver
SSL minimum protocol version. option - tls1-2
Option Description
tls1-0 TLS version 1.0.
tls1-1 TLS version 1.1.
tls1-2 TLS version 1.2.
tls1-3 TLS version 1.3.
status Enable/disable SSL-VPN. option - enable
Option Description
enable Enable SSL-VPN.
disable Disable SSL-VPN.
transform-
backward-
slashes
Transform backward slashes to forward slashes
in URLs.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
tunnel-addr-
assigned-
method
Method used for assigning address for tunnel. option - first-available
Option Description
first-available Assign the first available address from the pools.
round-robin Assign the available address from the pool with a round robin fashion.
tunnel-connect-
without-reauth
Enable/disable tunnel connection without re-
authorization if previous connection dropped.
option - disable
Option Description
enable Enable tunnel connection without re-authorization.
disable Disable tunnel connection without re-authorization.
tunnel-ip-pools
<name>
Names of the IPv4 IP Pool firewall objects that
define the IP addresses reserved for remote
clients.
Address name.
string Maximum
length: 79
tunnel-ipv6-
pools <name>
Names of the IPv6 IP Pool firewall objects that
define the IP addresses reserved for remote
clients.
Address name.
string Maximum
length: 79
tunnel-user-
session-timeout
Number of seconds after which user sessions
are cleaned up after tunnel connection is
dropped.
integer Minimum
value: 1
Maximum
value: 86400
30
unsafe-legacy-
renegotiation
Enable/disable unsafe legacy re-negotiation. option - disable
Option Description
enable Enable setting.
disable Disable setting.
url-obscuration Enable/disable to obscure the host name of the
URL of the web browser display.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
user-peer Name of user peer. string Maximum
length: 35
wins-server1 WINS server 1. ipv4-
address
Not Specified 0.0.0.0
wins-server2 WINS server 2. ipv4-
address
Not Specified 0.0.0.0
x-content-type-
options
Add HTTP X-Content-Type-Options header. option - enable
Option Description
enable Enable setting.
disable Disable setting.
ztna-trusted-
client
Enable/disable verification of device certificate
for SSLVPN ZTNA session.
option - disable
Option Description
enable Enable verification of device certificate for SSLVPN ZTNA session.
disable Disable verification of device certificate for SSLVPN ZTNA session.
config authentication-rule
Parameter Description Type Size Default
auth SSL-VPN authentication method restriction. option - any
Option Description
any Any
local Local
radius RADIUS
tacacs+ TACACS+
ldap LDAP
peer PEER
cipher SSL-VPN cipher strength. option - high
Option Description
any Any cipher strength.
Parameter Description Type Size Default
Option Description
high High cipher strength (>= 168 bits).
medium Medium cipher strength (>= 128 bits).
client-cert Enable/disable SSL-VPN client certificate restrictive. option - disable
Option Description
enable Enable setting.
disable Disable setting.
groups
<name>
User groups.
Group name.
string Maximum
length: 79
id ID. integer Minimum
value: 0
Maximum
value:
4294967295
0
portal SSL-VPN portal. string Maximum
length: 35
realm SSL-VPN realm. string Maximum
length: 35
source-
address
<name>
Source address of incoming traffic.
Address name.
string Maximum
length: 79
source-
address-
negate
Enable/disable negated source address match. option - disable
Option Description
enable Enable setting.
disable Disable setting.
source-
address6
<name>
IPv6 source address of incoming traffic.
IPv6 address name.
string Maximum
length: 79
source-
address6-
negate
Enable/disable negated source IPv6 address match. option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
source-
interface
<name>
SSL-VPN source interface of incoming traffic.
Interface name.
string Maximum
length: 35
user-peer Name of user peer. string Maximum
length: 35
users <name> User name.
User name.
string Maximum
length: 79

### config vpn ssl web host-check-software

SSL-VPN host check software.

#### Syntax

config vpn ssl web host-check-software
Description: SSL-VPN host check software.
edit <name>
config check-item-list
Description: Check item list.
edit <id>
set action [require|deny]
set md5s <id1>, <id2>, ...
set target {string}
set type [file|registry|...]
set version {string}
next
end
set guid {user}
set os-type [windows|macos]
set type [av|fw]
set version {string}
next
end

#### Parameters

config vpn ssl web host-check-software
Parameter Description Type Size Default
guid Globally unique ID. user Not
Specified
name Name. string Maximum
length: 63
Parameter Description Type Size Default
os-type OS type. option - windows
Option Description
windows Microsoft Windows operating system.
macos Apple MacOS operating system.
type Type. option - av
Option Description
av AntiVirus.
fw Firewall.
version Version. string Maximum
length: 35
config check-item-list
Parameter Description Type Size Default
action Action. option - require
Option Description
require Require.
deny Deny.
id ID. integer Minimum
value: 0
Maximum
value:
65535
0
md5s <id> MD5 checksum.
Hex string of MD5 checksum.
string Maximum
length: 32
target Target. string Maximum
length: 255
type Type. option - file
Option Description
file File.
registry Registry.
process Process.
Parameter Description Type Size Default
version Version. string Maximum
length: 35

### config vpn ssl web portal

Portal.

#### Syntax

config vpn ssl web portal
Description: Portal.
edit <name>
set allow-user-access {option1}, {option2}, ...
set auto-connect [enable|disable]
config bookmark-group
Description: Portal bookmark group.
edit <name>
config bookmarks
Description: Bookmark table.
edit <name>
set additional-params {var-string}
set apptype [ftp|rdp|...]
set color-depth [32|16|...]
set description {var-string}
set domain {var-string}
set folder {var-string}
config form-data
Description: Form data.
edit <name>
set value {var-string}
next
end
set height {integer}
set host {var-string}
set keyboard-layout [ar-101|ar-102|...]
set load-balancing-info {var-string}
set logon-password {password}
set logon-user {var-string}
set port {integer}
set preconnection-blob {var-string}
set preconnection-id {integer}
set restricted-admin [enable|disable]
set security [any|rdp|...]
set send-preconnection-id [enable|disable]
set sso [disable|static|...]
set sso-credential [sslvpn-login|alternative]
set sso-credential-sent-once [enable|disable]
set sso-password {password}
set sso-username {var-string}
set url {var-string}
set vnc-keyboard-layout [default|da|...]
set width {integer}
next
end
next
end
set client-src-range [enable|disable]
set clipboard [enable|disable]
set custom-lang {string}
set customize-forticlient-download-url [enable|disable]
set default-protocol [web|ftp|...]
set default-window-height {integer}
set default-window-width {integer}
set dhcp-ip-overlap [use-new|use-old]
set dhcp-ra-giaddr {ipv4-address}
set dhcp6-ra-linkaddr {ipv6-address}
set display-bookmark [enable|disable]
set display-connection-tools [enable|disable]
set display-history [enable|disable]
set display-status [enable|disable]
set dns-server1 {ipv4-address}
set dns-server2 {ipv4-address}
set dns-suffix {var-string}
set exclusive-routing [enable|disable]
set focus-bookmark [enable|disable]
set forticlient-download [enable|disable]
set forticlient-download-method [direct|ssl-vpn]
set heading {string}
set hide-sso-credential [enable|disable]
set host-check [none|av|...]
set host-check-interval {integer}
set host-check-policy <name1>, <name2>, ...
set ip-mode [range|user-group|...]
set ip-pools <name1>, <name2>, ...
set ipv6-dns-server1 {ipv6-address}
set ipv6-dns-server2 {ipv6-address}
set ipv6-exclusive-routing [enable|disable]
set ipv6-pools <name1>, <name2>, ...
set ipv6-service-restriction [enable|disable]
set ipv6-split-tunneling [enable|disable]
set ipv6-split-tunneling-routing-address <name1>, <name2>, ...
set ipv6-split-tunneling-routing-negate [enable|disable]
set ipv6-tunnel-mode [enable|disable]
set ipv6-wins-server1 {ipv6-address}
set ipv6-wins-server2 {ipv6-address}
set keep-alive [enable|disable]
config landing-page
Description: Landing page options.
config form-data
Description: Form data.
edit <name>
set value {var-string}
next
end
set sso [disable|static|...]
set sso-credential [sslvpn-login|alternative]
set sso-password {password}
set sso-username {var-string}
set url {var-string}
end
set landing-page-mode [enable|disable]
set limit-user-logins [enable|disable]
set mac-addr-action [allow|deny]
set mac-addr-check [enable|disable]
config mac-addr-check-rule
Description: Client MAC address check rule.
edit <name>
set mac-addr-list <addr1>, <addr2>, ...
set mac-addr-mask {integer}
next
end
set macos-forticlient-download-url {var-string}
set os-check [enable|disable]
config os-check-list
Description: SSL-VPN OS checks. Read-only.
edit <name>
set action [deny|allow|...]
set latest-patch-level {user}
set tolerance {integer}
next
end
set prefer-ipv6-dns [enable|disable]
set redir-url {var-string}
set rewrite-ip-uri-ui [enable|disable]
set save-password [enable|disable]
set service-restriction [enable|disable]
set skip-check-for-browser [enable|disable]
set skip-check-for-unsupported-os [enable|disable]
set smb-max-version [smbv1|smbv2|...]
set smb-min-version [smbv1|smbv2|...]
set smb-ntlmv1-auth [enable|disable]
set smbv1 [enable|disable]
config split-dns
Description: Split DNS for SSL-VPN.
edit <id>
set dns-server1 {ipv4-address}
set dns-server2 {ipv4-address}
set domains {var-string}
set ipv6-dns-server1 {ipv6-address}
set ipv6-dns-server2 {ipv6-address}
next
end
set split-tunneling [enable|disable]
set split-tunneling-routing-address <name1>, <name2>, ...
set split-tunneling-routing-negate [enable|disable]
set theme [jade|neutrino|...]
set tunnel-mode [enable|disable]
set use-sdwan [enable|disable]
set user-bookmark [enable|disable]
set user-group-bookmark [enable|disable]
set web-mode [enable|disable]
set windows-forticlient-download-url {var-string}
set wins-server1 {ipv4-address}
set wins-server2 {ipv4-address}
next
end

#### Parameters

config vpn ssl web portal
Parameter Description Type Size Default
allow-user-
access
Allow user access to SSL-VPN applications. option - web ftp
smb sftp
telnet ssh
vnc rdp
ping
Option Description
web HTTP/HTTPS access.
ftp FTP access.
smb SMB/CIFS access.
sftp SFTP access.
telnet TELNET access.
ssh SSH access.
vnc VNC access.
rdp RDP access.
ping PING access.
auto-connect Enable/disable automatic connect by client when
system is up.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
client-src-range Allow client to add source range for the tunnel traffic. option - disable
Option Description
enable Enable setting.
disable Disable setting.
clipboard Enable to support RDP/VPC clipboard functionality. option - enable
Option Description
enable Enable support of RDP/VNC clipboard.
disable Disable support of RDP/VNC clipboard.
Parameter Description Type Size Default
custom-lang Change the web portal display language. Overrides
config system global set language. You can use config
system custom-language and execute system custom-
language to add custom language files.
string Maximum
length: 35
customize-
forticlient-
download-url
Enable support of customized download URL for
FortiClient.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
default-protocol Application type that is set by default. option - web
Option Description
web HTTP/HTTPS.
ftp FTP.
telnet Telnet.
smb SMB/CIFS.
vnc VNC.
rdp RDP.
ssh SSH.
sftp SFTP.
default-window-
height
Screen height. integer Minimum
value: 0
Maximum
value:
65535
768
default-window-
width
Screen width. integer Minimum
value: 0
Maximum
value:
65535
1024
dhcp-ip-overlap Configure overlapping DHCP IP allocation
assignment.
option - use-new
Parameter Description Type Size Default
Option Description
use-new Assign DHCP lease to new client and remove old client lease.
use-old Preserve previous client IP allocation and disconnect new client.
dhcp-ra-giaddr Relay agent gateway IP address to use in the giaddr
field of DHCP requests.
ipv4-
address
Not
Specified
0.0.0.0
dhcp6-ra-
linkaddr
Relay agent IPv6 link address to use in DHCP6
requests.
ipv6-
address
Not
Specified
::
display-
bookmark
Enable to display the web portal bookmark widget. option - enable
Option Description
enable Enable setting.
disable Disable setting.
display-
connection-
tools
Enable to display the web portal connection tools
widget.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
display-history Enable to display the web portal user login history
widget.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
display-status Enable to display the web portal status widget. option - enable
Option Description
enable Enable setting.
disable Disable setting.
dns-server1 IPv4 DNS server 1. ipv4-
address
Not
Specified
0.0.0.0
dns-server2 IPv4 DNS server 2. ipv4-
address
Not
Specified
0.0.0.0
Parameter Description Type Size Default
dns-suffix DNS suffix. var-string Maximum
length: 253
exclusive-
routing
Enable/disable all traffic go through tunnel only. option - disable
Option Description
enable Enable setting.
disable Disable setting.
focus-
bookmark
Enable to prioritize the placement of the bookmark
section over the quick-connection section in the SSL-
VPN application.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
forticlient-
download
Enable/disable download option for FortiClient. option - enable
Option Description
enable Enable setting.
disable Disable setting.
forticlient-
download-
method
FortiClient download method. option - direct
Option Description
direct Download via direct link.
ssl-vpn Download via SSL-VPN.
heading Web portal heading message. string Maximum
length: 31
SSL-VPN
Portal
hide-sso-
credential
Enable to prevent SSO credential being sent to client. option - enable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
host-check Type of host checking performed on endpoints. option - none
Option Description
none No host checking.
av AntiVirus software recognized by the Windows Security Center.
fw Firewall software recognized by the Windows Security Center.
av-fw AntiVirus and firewall software recognized by the Windows Security Center.
custom Custom.
host-check-
interval
Periodic host check interval. Value of 0 means
disabled and host checking only happens when the
endpoint connects.
integer Minimum
value: 120
Maximum
value:
259200
0
host-check-
policy <name>
One or more policies to require the endpoint to have
specific security software.
Host check software list name.
string Maximum
length: 79
ip-mode Method by which users of this SSL-VPN tunnel obtain
IP addresses.
option - range
Option Description
range Use the IP addresses available for all SSL-VPN users as defined by the SSL
settings command.
user-group Use the IP addresses associated with individual users or user groups
(usually from external auth servers).
dhcp Use IP addresses obtained from external DHCP server.
no-ip Do not assign IP address.
ip-pools
<name>
IPv4 firewall source address objects reserved for SSL-
VPN tunnel mode clients.
Address name.
string Maximum
length: 79
ipv6-dns-
server1
IPv6 DNS server 1. ipv6-
address
Not
Specified
::
ipv6-dns-
server2
IPv6 DNS server 2. ipv6-
address
Not
Specified
::
ipv6-exclusive-
routing
Enable/disable all IPv6 traffic go through tunnel only. option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
ipv6-pools
<name>
IPv6 firewall source address objects reserved for SSL-
VPN tunnel mode clients.
Address name.
string Maximum
length: 79
ipv6-service-
restriction
Enable/disable IPv6 tunnel service restriction. option - disable
Option Description
enable Enable setting.
disable Disable setting.
ipv6-split-
tunneling
Enable/disable IPv6 split tunneling. option - enable
Option Description
enable Enable setting.
disable Disable setting.
ipv6-split-
tunneling-
routing-address
<name>
IPv6 SSL-VPN tunnel mode firewall address objects
that override firewall policy destination addresses to
control split-tunneling access.
Address name.
string Maximum
length: 79
ipv6-split-
tunneling-
routing-negate
Enable to negate IPv6 split tunneling routing address. option - disable
Option Description
enable Enable setting.
disable Disable setting.
ipv6-tunnel-
mode
Enable/disable IPv6 SSL-VPN tunnel mode. option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
ipv6-wins-
server1
IPv6 WINS server 1. ipv6-
address
Not
Specified
::
ipv6-wins-
server2
IPv6 WINS server 2. ipv6-
address
Not
Specified
::
keep-alive Enable/disable automatic reconnect for FortiClient
connections.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
landing-page-
mode
Enable/disable SSL-VPN landing page mode. option - disable
Option Description
enable Enable setting.
disable Disable setting.
limit-user-logins Enable to limit each user to one SSL-VPN session at a
time.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
mac-addr-
action
Client MAC address action. option - allow
Option Description
allow Allow connection when client MAC address is matched.
deny Deny connection when client MAC address is matched.
mac-addr-
check
Enable/disable MAC address host checking. option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
macos-
forticlient-
download-url
Download URL for Mac FortiClient. var-string Maximum
length: 1023
name Portal name. string Maximum
length: 35
os-check Enable to let the FortiGate decide action based on
client OS.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
prefer-ipv6-dns Prefer to query IPv6 DNS server first if enabled. option - disable
Option Description
enable Enable setting.
disable Disable setting.
redir-url Client login redirect URL. var-string Maximum
length: 255
rewrite-ip-uri-ui Rewrite contents for URI contains IP and /ui/. option - disable
Option Description
enable Enable contents rewrite for URI contains "IP-address/ui/".
disable Disable contents rewrite for URI contains "IP-address/ui/".
save-password Enable/disable FortiClient saving the user's password. option - disable
Option Description
enable Enable setting.
disable Disable setting.
service-
restriction
Enable/disable tunnel service restriction. option - disable
Option Description
enable Enable setting.
disable Disable setting.
Parameter Description Type Size Default
skip-check-for-
browser
Enable to skip host check for browser support. option - enable
Option Description
enable Enable setting.
disable Disable setting.
skip-check-for-
unsupported-os
Enable to skip host check if client OS does not support
it.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
smb-max-
version
SMB maximum client protocol version. option - smbv3
Option Description
smbv1 SMB version 1.
smbv2 SMB version 2.
smbv3 SMB version 3.
smb-min-
version
SMB minimum client protocol version. option - smbv2
Option Description
smbv1 SMB version 1.
smbv2 SMB version 2.
smbv3 SMB version 3.
smb-ntlmv1-
auth
Enable support of NTLMv1 for Samba authentication. option - disable
Option Description
enable Enable setting.
disable Disable setting.
smbv1 SMB version 1. option - disable
Parameter Description Type Size Default
Option Description
enable enable
disable disable
split-tunneling Enable/disable IPv4 split tunneling. option - enable
Option Description
enable Enable setting.
disable Disable setting.
split-tunneling-
routing-address
<name>
IPv4 SSL-VPN tunnel mode firewall address objects
that override firewall policy destination addresses to
control split-tunneling access.
Address name.
string Maximum
length: 79
split-tunneling-
routing-negate
Enable to negate split tunneling routing address. option - disable
Option Description
enable Enable setting.
disable Disable setting.
theme Web portal color scheme. option - security-
fabric
Option Description
jade Jade theme.
neutrino Neutrino theme.
mariner Mariner theme.
graphite Graphite theme.
melongene Melongene theme.
jet-stream Jet Stream theme.
security-fabric Security Fabric theme.
dark-matter Dark Matter theme.
onyx Onyx theme.
eclipse Eclipse theme.
tunnel-mode Enable/disable IPv4 SSL-VPN tunnel mode. option - disable
Parameter Description Type Size Default
Option Description
enable Enable setting.
disable Disable setting.
use-sdwan Use SD-WAN rules to get output interface. option - disable
Option Description
enable Enable setting.
disable Disable setting.
user-bookmark Enable to allow web portal users to create their own
bookmarks.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
user-group-
bookmark
Enable to allow web portal users to create bookmarks
for all users in the same user group.
option - enable
Option Description
enable Enable setting.
disable Disable setting.
web-mode Enable/disable SSL-VPN web mode. option - disable
Option Description
enable Enable setting.
disable Disable setting.
windows-
forticlient-
download-url
Download URL for Windows FortiClient. var-string Maximum
length: 1023
wins-server1 IPv4 WINS server 1. ipv4-
address
Not
Specified
0.0.0.0
wins-server2 IPv4 WINS server 1. ipv4-
address
Not
Specified
0.0.0.0
config bookmark-group
Parameter Description Type Size Default
name Bookmark group name. string Maximum
length: 35
config bookmarks
Parameter Description Type Size Default
additional-
params
Additional parameters. var-string Maximum
length: 128
apptype Application type. option - web
Option Description
ftp FTP.
rdp RDP.
sftp SFTP.
smb SMB/CIFS.
ssh SSH.
telnet Telnet.
vnc VNC.
web HTTP/HTTPS.
color-depth Color depth per pixel. option - 16
Option Description
32 32bits per pixel.
16 16bits per pixel.
8 8bits per pixel.
description Description. var-string Maximum
length: 128
domain Login domain. var-string Maximum
length: 128
folder Network shared file folder parameter. var-string Maximum
length: 128
Parameter Description Type Size Default
height Screen height. integer Minimum
value: 0
Maximum
value: 65535
0
host Host name/IP parameter. var-string Maximum
length: 128
keyboard-layout Keyboard layout. option - en-us
Option Description
ar-101 Arabic (101).
ar-102 Arabic (102).
ar-102-azerty Arabic (102) AZERTY.
can-mul Canadian Multilingual Standard.
cz Czech.
cz-qwerty Czech (QWERTY).
cz-pr Czech Programmers.
da Danish.
nl Dutch.
de German.
de-ch German, Switzerland.
de-ibm German (IBM).
en-uk English, United Kingdom.
en-uk-ext English, United Kingdom Extended.
en-us English, United States.
en-us-dvorak English, United States-Dvorak.
es Spanish.
es-var Spanish Variation.
fi Finnish.
fi-sami Finnish with Sami.
fr French.
fr-apple French, Apple.
fr-ca French, Canada.
Parameter Description Type Size Default
Option Description
fr-ch French, Switzerland.
fr-be French, Belgium.
hr Croatian.
hu Hungarian.
hu-101 Hungarian 101-Key.
it Italian.
it-142 Italian (142).
ja Japanese.
ja-106 Japanese 106/109 key.
ko Korean.
la-am Latin American.
lt Lithuanian.
lt-ibm Lithuanian IBM.
lt-std Lithuanian Standard.
lav-std Latvian (Standard).
lav-leg Latvian (Legacy).
mk Macedonian (FYROM).
mk-std Macedonia (FYROM) - Standard.
no Norwegian.
no-sami Norwegian with Sami.
pol-214 Polish (214).
pol-pr Polish (Programmers).
pt Portuguese.
pt-br Portuguese (Brazilian ABNT).
pt-br-abnt2 Portuguese (Brazilian ABNT2).
ru Russian.
ru-mne Russian - Mnemonic.
ru-t Russian (Typewriter).
sl Slovenian.
Parameter Description Type Size Default
Option Description
sv Swedish.
sv-sami Swedish with Sami.
tuk Turkmen.
tur-f Turkish F.
tur-q Turkish Q.
zh-sym-sg-us Chinese (Simplified, Singapore) - US keyboard.
zh-sym-us Chinese (Simplified) - US Keyboard.
zh-tr-hk Chinese (Traditional, Hong Kong S.A.R.).
zh-tr-mo Chinese (Traditional Macao S.A.R.) - US Keyboard.
zh-tr-us Chinese (Traditional) - US keyboard.
load-balancing-
info
The load balancing information or cookie which
should be provided to the connection broker.
var-string Maximum
length: 511
logon-password Logon password. password Not Specified
logon-user Logon user. var-string Maximum
length: 35
name Bookmark name. string Maximum
length: 35
port Remote port. integer Minimum
value: 0
Maximum
value: 65535
0
preconnection-
blob
An arbitrary string which identifies the RDP
source.
var-string Maximum
length: 511
preconnection-id The numeric ID of the RDP source. integer Minimum
value: 0
Maximum
value:
4294967295
0
restricted-admin Enable/disable restricted admin mode for RDP. option - disable
Option Description
enable Enable restricted admin mode for RDP.
disable Disable restricted admin mode for RDP.
Parameter Description Type Size Default
security Security mode for RDP connection. option - any
Option Description
any Allow the server to choose the type of security.
rdp Standard RDP encryption.
nla Network Level Authentication.
tls TLS encryption.
send-
preconnection-id
Enable/disable sending of preconnection ID. option - disable
Option Description
enable Enable sending of preconnection ID.
disable Disable sending of preconnection ID.
sso Single sign-on. option - disable
Option Description
disable Disable SSO.
static Static SSO.
auto Auto SSO.
sso-credential Single sign-on credentials. option - sslvpn-
login
Option Description
sslvpn-login SSL-VPN login.
alternative Alternative.
sso-credential-
sent-once
Single sign-on credentials are only sent once to
remote server.
option - disable
Option Description
enable Single sign-on credentials are only sent once to remote server.
disable Single sign-on credentials are sent to remote server for every HTTP
request.
sso-password SSO password. password Not Specified
sso-username SSO user name. var-string Maximum
length: 35
Parameter Description Type Size Default
url URL parameter. var-string Maximum
length: 128
vnc-keyboard-
layout
Keyboard layout. option - default
Option Description
default Default.
da Danish.
nl Dutch.
en-uk English, United Kingdom.
en-uk-ext English, United Kingdom Extended.
fi Finnish.
fr French.
fr-be French, Belgium.
fr-ca-mul French, Canadian Multilingual Std.
de German.
de-ch German, Switzerland.
it Italian.
it-142 Italian (142).
pt Portuguese.
pt-br-abnt2 Portuguese (Brazilian ABNT2).
no Norwegian.
gd Scottish Gaelic.
es Spanish.
sv Swedish.
us-intl United States-International.
width Screen width. integer Minimum
value: 0
Maximum
value: 65535
0
config form-data
Parameter Description Type Size Default
name Name. string Maximum
length: 35
value Value. var-string Maximum
length: 63
config form-data
Parameter Description Type Size Default
name Name. string Maximum
length: 35
value Value. var-string Maximum
length: 63
config landing-page
Parameter Description Type Size Default
sso Single sign-on. option - disable
Option Description
disable Disable SSO.
static Static SSO.
auto Auto SSO.
sso-credential Single sign-on credentials. option - sslvpn-login
Option Description
sslvpn-login SSL-VPN login.
alternative Alternative.
sso-password SSO password. password Not
Specified
sso-username SSO user name. var-string Maximum
length: 35
url Landing page URL. var-string Maximum
length: 511
config form-data
Parameter Description Type Size Default
name Name. string Maximum
length: 35
value Value. var-string Maximum
length: 63
config form-data
Parameter Description Type Size Default
name Name. string Maximum
length: 35
value Value. var-string Maximum
length: 63
config mac-addr-check-rule
Parameter Description Type Size Default
mac-addr-list
<addr>
Client MAC address list.
Client MAC address.
mac-
address
Not
Specified
mac-addr-
mask
Client MAC address mask. integer Minimum
value: 1
Maximum
value: 48
48
name Client MAC address check rule name. string Maximum
length: 35
config os-check-list
Parameter Description Type Size Default
action OS check options. option - allow
Option Description
deny Deny all OS versions.
allow Allow any OS version.
check-up-to-date Verify OS is up-to-date.
latest-patch-
level
Latest OS patch level. user Not
Specified
0
Parameter Description Type Size Default
name Name. string Maximum
length: 35
tolerance OS patch level tolerance. integer Minimum
value: 0
Maximum
value:
65535
0
config split-dns
Parameter Description Type Size Default
dns-server1 DNS server 1. ipv4-
address
Not Specified 0.0.0.0
dns-server2 DNS server 2. ipv4-
address
Not Specified 0.0.0.0
domains Split DNS domains used for SSL-VPN clients
separated by comma.
var-string Maximum
length: 1024
id ID. integer Minimum
value: 0
Maximum
value:
4294967294
0
ipv6-dns-
server1
IPv6 DNS server 1. ipv6-
address
Not Specified ::
ipv6-dns-
server2
IPv6 DNS server 2. ipv6-
address
Not Specified ::

### config vpn ssl web realm

Realm.

#### Syntax

config vpn ssl web realm
Description: Realm.
edit <url-path>
set login-page {var-string}
set max-concurrent-user {integer}
set nas-ip {ipv4-address}
set radius-port {integer}
set radius-server {string}
set virtual-host {var-string}
set virtual-host-only [enable|disable]
set virtual-host-server-cert {string}
next
end

#### Parameters

config vpn ssl web realm
Parameter Description Type Size Default
login-page Replacement HTML for SSL-VPN login page. var-string Maximum
length:
32768
max-
concurrent-
user
Maximum concurrent users. integer Minimum
value: 0
Maximum
value:
65535
0
nas-ip IP address used as a NAS-IP to communicate with the
RADIUS server.
ipv4-
address
Not
Specified
0.0.0.0
radius-port RADIUS service port number. integer Minimum
value: 0
Maximum
value:
65535
0
radius-server RADIUS server associated with realm. string Maximum
length: 35
url-path URL path to access SSL-VPN login page. string Maximum
length: 35
virtual-host Virtual host name for realm. var-string Maximum
length: 255
virtual-host-
only
Enable/disable enforcement of virtual host method for
SSL-VPN client access.
option - disable
Option Description
enable Enable setting.
disable Disable setting.
virtual-host-
server-cert
Name of the server certificate to used for this realm. string Maximum
length: 35

### config vpn ssl web user-bookmark

Configure SSL-VPN user bookmark.

#### Syntax

config vpn ssl web user-bookmark
Description: Configure SSL-VPN user bookmark.
edit <name>
config bookmarks
Description: Bookmark table.
edit <name>
set additional-params {var-string}
set apptype [ftp|rdp|...]
set color-depth [32|16|...]
set description {var-string}
set domain {var-string}
set folder {var-string}
config form-data
Description: Form data.
edit <name>
set value {var-string}
next
end
set height {integer}
set host {var-string}
set keyboard-layout [ar-101|ar-102|...]
set load-balancing-info {var-string}
set logon-password {password}
set logon-user {var-string}
set port {integer}
set preconnection-blob {var-string}
set preconnection-id {integer}
set restricted-admin [enable|disable]
set security [any|rdp|...]
set send-preconnection-id [enable|disable]
set sso [disable|static|...]
set sso-credential [sslvpn-login|alternative]
set sso-credential-sent-once [enable|disable]
set sso-password {password}
set sso-username {var-string}
set url {var-string}
set vnc-keyboard-layout [default|da|...]
set width {integer}
next
end
set custom-lang {string}
next
end

#### Parameters

config vpn ssl web user-bookmark
Parameter Description Type Size Default
custom-lang Personal language. string Maximum
length: 35
name User and group name. string Maximum
length: 101
config bookmarks
Parameter Description Type Size Default
additional-
params
Additional parameters. var-string Maximum
length: 128
apptype Application type. option - web
Option Description
ftp FTP.
rdp RDP.
sftp SFTP.
smb SMB/CIFS.
ssh SSH.
telnet Telnet.
vnc VNC.
web HTTP/HTTPS.
color-depth Color depth per pixel. option - 16
Option Description
32 32bits per pixel.
16 16bits per pixel.
8 8bits per pixel.
description Description. var-string Maximum
length: 128
domain Login domain. var-string Maximum
length: 128
folder Network shared file folder parameter. var-string Maximum
length: 128
height Screen height. integer Minimum
value: 0
Maximum
value: 65535
0
host Host name/IP parameter. var-string Maximum
length: 128
keyboard-layout Keyboard layout. option - en-us
Parameter Description Type Size Default
Option Description
ar-101 Arabic (101).
ar-102 Arabic (102).
ar-102-azerty Arabic (102) AZERTY.
can-mul Canadian Multilingual Standard.
cz Czech.
cz-qwerty Czech (QWERTY).
cz-pr Czech Programmers.
da Danish.
nl Dutch.
de German.
de-ch German, Switzerland.
de-ibm German (IBM).
en-uk English, United Kingdom.
en-uk-ext English, United Kingdom Extended.
en-us English, United States.
en-us-dvorak English, United States-Dvorak.
es Spanish.
es-var Spanish Variation.
fi Finnish.
fi-sami Finnish with Sami.
fr French.
fr-apple French, Apple.
fr-ca French, Canada.
fr-ch French, Switzerland.
fr-be French, Belgium.
hr Croatian.
hu Hungarian.
hu-101 Hungarian 101-Key.
it Italian.
Parameter Description Type Size Default
Option Description
it-142 Italian (142).
ja Japanese.
ja-106 Japanese 106/109 key.
ko Korean.
la-am Latin American.
lt Lithuanian.
lt-ibm Lithuanian IBM.
lt-std Lithuanian Standard.
lav-std Latvian (Standard).
lav-leg Latvian (Legacy).
mk Macedonian (FYROM).
mk-std Macedonia (FYROM) - Standard.
no Norwegian.
no-sami Norwegian with Sami.
pol-214 Polish (214).
pol-pr Polish (Programmers).
pt Portuguese.
pt-br Portuguese (Brazilian ABNT).
pt-br-abnt2 Portuguese (Brazilian ABNT2).
ru Russian.
ru-mne Russian - Mnemonic.
ru-t Russian (Typewriter).
sl Slovenian.
sv Swedish.
sv-sami Swedish with Sami.
tuk Turkmen.
tur-f Turkish F.
tur-q Turkish Q.
zh-sym-sg-us Chinese (Simplified, Singapore) - US keyboard.
Parameter Description Type Size Default
Option Description
zh-sym-us Chinese (Simplified) - US Keyboard.
zh-tr-hk Chinese (Traditional, Hong Kong S.A.R.).
zh-tr-mo Chinese (Traditional Macao S.A.R.) - US Keyboard.
zh-tr-us Chinese (Traditional) - US keyboard.
load-balancing-
info
The load balancing information or cookie which
should be provided to the connection broker.
var-string Maximum
length: 511
logon-password Logon password. password Not Specified
logon-user Logon user. var-string Maximum
length: 35
name Bookmark name. string Maximum
length: 35
port Remote port. integer Minimum
value: 0
Maximum
value: 65535
0
preconnection-
blob
An arbitrary string which identifies the RDP
source.
var-string Maximum
length: 511
preconnection-id The numeric ID of the RDP source. integer Minimum
value: 0
Maximum
value:
4294967295
0
restricted-admin Enable/disable restricted admin mode for RDP. option - disable
Option Description
enable Enable restricted admin mode for RDP.
disable Disable restricted admin mode for RDP.
security Security mode for RDP connection. option - any
Option Description
any Allow the server to choose the type of security.
rdp Standard RDP encryption.
nla Network Level Authentication.
tls TLS encryption.
Parameter Description Type Size Default
send-
preconnection-id
Enable/disable sending of preconnection ID. option - disable
Option Description
enable Enable sending of preconnection ID.
disable Disable sending of preconnection ID.
sso Single sign-on. option - disable
Option Description
disable Disable SSO.
static Static SSO.
auto Auto SSO.
sso-credential Single sign-on credentials. option - sslvpn-
login
Option Description
sslvpn-login SSL-VPN login.
alternative Alternative.
sso-credential-
sent-once
Single sign-on credentials are only sent once to
remote server.
option - disable
Option Description
enable Single sign-on credentials are only sent once to remote server.
disable Single sign-on credentials are sent to remote server for every HTTP
request.
sso-password SSO password. password Not Specified
sso-username SSO user name. var-string Maximum
length: 35
url URL parameter. var-string Maximum
length: 128
vnc-keyboard-
layout
Keyboard layout. option - default
Option Description
default Default.
da Danish.
Parameter Description Type Size Default
Option Description
nl Dutch.
en-uk English, United Kingdom.
en-uk-ext English, United Kingdom Extended.
fi Finnish.
fr French.
fr-be French, Belgium.
fr-ca-mul French, Canadian Multilingual Std.
de German.
de-ch German, Switzerland.
it Italian.
it-142 Italian (142).
pt Portuguese.
pt-br-abnt2 Portuguese (Brazilian ABNT2).
no Norwegian.
gd Scottish Gaelic.
es Spanish.
sv Swedish.
us-intl United States-International.
width Screen width. integer Minimum
value: 0
Maximum
value: 65535
0
config form-data
Parameter Description Type Size Default
name Name. string Maximum
length: 35
value Value. var-string Maximum
length: 63

### config vpn ssl web user-group-bookmark

Configure SSL-VPN user group bookmark.