# Cisco Secure Firewall Threat Defense (FTD) Management CLI Reference

> Refined from the provided Cisco FTD management-interface reference. Non-CLI navigation, GUI screenshots/OCR debris, deployment diagrams, duplicated prose, and unrelated document metadata were removed. CLI commands, example values, command output, version notes, and relevant technical meaning are preserved.

## Scope and Version Context

This reference covers CLI information related to the FTD management interface.

FTD software versions 7.4 and later support merged Management and Diagnostic interfaces, also known as the Converged Management Interface (CMI).

CMI is enabled by default, and can be disabled by users.

The source document is mainly applicable to firewalls with disabled CMI (unmerged diagnostic and management interfaces).

## Command Index

| Area | Command |
|---|---|
| CMI status | `show management-interface convergence` |
| Interface IP status | `show interface ip brief` |
| Platform / interface verification | `show tech-support` |
| Configure management IPv4 | `configure network ipv4 manual 10.1.1.2 255.0.0.0 10.1.1.1` |
| Restrict management SSH access | `configure ssh-access-list 10.0.0.0/8` |
| Show FTD management network | `show network` |
| Show LINA management interface | `show run interface m1/1` |
| Show management mode | `show managers` |
| Enter FXOS | `connect fxos` |
| Connect to module console | `connect module 1 console` |
| Connect to FTD from module | `connect ftd` |
| Show interface details | `show interface` |

---

## FTD 7.4 and Later — Converged Management Interface (CMI)

As of 7.4, by default the firewall uses the Converged Management Interface (CMI) mode.

### `show management-interface convergence`

```text
FTD3100# show management-interface convergence
management-interface convergence
```

NAT is used as an internal implementation of CMI:

- An internal private IPv4 address (`203.0.113.130`) is automatically configured in data plane for IPv4.
- An internal private IPv6 address (`fd00:0:1:1::2`) is automatically configured in data plane for IPv6.

### `show interface ip brief`

```text
FTD3100# show interface ip brief

Interface                  IP-Address      OK?           Method Status      Protocol
Internal-Data0/1           unassigned      YES           unset  up          up
Port-channel5              192.0.2.1       YES           unset  up          up
Ethernet1/1                unassigned      YES           unset  admin down  down
Ethernet1/2                unassigned      YES           unset  admin down  down
Ethernet1/5                unassigned      YES           unset  admin down  down
Ethernet1/6                unassigned      YES           unset  admin down  down
Ethernet1/7                unassigned      YES           unset  admin down  down
Ethernet1/8                unassigned      YES           unset  admin down  down
Ethernet1/9                unassigned      YES           unset  admin down  down
Ethernet1/10               unassigned      YES           unset  admin down  down
Ethernet1/11               unassigned      YES           unset  admin down  down
Ethernet1/12               unassigned      YES           unset  admin down  down
Ethernet1/13               unassigned      YES           unset  admin down  down
Ethernet1/14               unassigned      YES           unset  admin down  down
Ethernet1/15               unassigned      YES           unset  admin down  down
Ethernet1/16               unassigned      YES           unset  admin down  down
Internal-Control1/1        unassigned      YES           unset  up          up
Internal-Data1/1           169.254.1.1     YES           unset  up          up
Internal-Data1/2           unassigned      YES           unset  up          up
Management1/1              203.0.113.130   YES           unset  up          up
```

---

## Pre-7.4 Releases — Management Interface on ASA 5500-X Devices

When an FTD image is installed on an ASA 55xx device, the management interface is shown as `Management1/1`. On 5512/15/25/45/55-X devices this becomes `Management0/0`.

This can be verified from FTD CLI with `show tech-support`.

### ASA5508-X — `show tech-support`

```text
> show tech-support
```

Relevant management-interface line from the source output:

```text
13: Ext: Management1/1       : address is d8b1.90ab.c851, irq 0
```

### ASA5512-X — `show tech-support`

```text
> show tech-support
```

Relevant management-interface line from the source output:

```text
9: Ext: Management0/0       : address is a89d.21ce.fde6, irq 0
```

---

## Pre-7.4 Management Interface Architecture

The Management interface is divided into two logical interfaces:

- `br1` (`management0` on FPR2100/4100/9300 appliances)
- `diagnostic`

### `br1` / `management0`

Purpose from the source:

- Used to assign the FTD IP used for FTD/FMC communication.
- Terminates the sftunnel between FMC/FTD.
- Used as a source for rule-based syslogs.
- Provides SSH and HTTPS access to the FTD box.

Mandatory: **Yes**, since it is used for FTD/FMC communication and the sftunnel terminates on it.

### `diagnostic`

Purpose from the source:

- Provides remote access (for example, SNMP) to the ASA engine.
- Used as a source for LINA-level syslogs, AAA, SNMP, etc. messages.

Mandatory: **No**. The source states that it is not recommended to configure it and recommends using a data interface instead.

### Configure Management IPv4

The source states that this interface is configured during FTD installation (setup). The `br1` settings can later be modified as follows:

```text
> configure network ipv4 manual 10.1.1.2 255.0.0.0 10.1.1.1
Setting IPv4 network configuration.
Network settings changed.
>
```

### Restrict SSH Access

By default, only the `admin` user can connect to the FTD `br1` subinterface.

To restrict SSH access with the CLISH CLI:

```text
> configure ssh-access-list 10.0.0.0/8
```

### Verify from FTD CLI — `show network`

```text
> show network
...
=======[ br1 ]=======
State : Enabled
Channels : Management & Events
Mode :
MDI/MDIX : Auto/MDIX
MTU : 1500
MAC Address : 18:8B:9D:1E:CA:7B
----------------------[ IPv4 ]-----
Configuration : Manual
Address : 10.1.1.2
Netmask : 255.0.0.0
Broadcast : 10.1.1.255
----------------------[ IPv6 ]-----
```

### Verify from LINA CLI

#### `show interface ip brief`

```text
firepower# show interface ip brief
..
Management1/1 192.168.1.1 YES unset up up
```

#### `show run interface m1/1`

```text
firepower# show run interface m1/1
!
interface Management1/1
management-only
nameif diagnostic
security-level 0
ip address 192.168.1.1 255.255.255.0
```

---

## FDM On-Box Management

An FTD installed on ASA5500-X appliances can be managed either by FMC (off-box management) or Firepower Device Manager (FDM) (on-box management).

### `show managers`

Output from FTD CLISH when the device is managed by FDM:

```text
> show managers
Managed locally.
>
```

The source states that FDM uses the `br1` logical interface.

---

## Firepower Hardware Appliances

FTD can be installed on Firepower 2100, 4100, and 9300 hardware appliances. The Firepower chassis runs FXOS while FTD is installed on a module/blade.

The source states:

- On FPR4100/9300, the chassis management interface cannot be used/shared with the FTD software running inside the FP module. A separate data interface is allocated for FTD management.
- On FPR2100, this interface is shared between the chassis (FXOS) and the FTD logical appliance.

### FPR2100 — `show network`

```text
> show network
===============[ System Information ]===============
Hostname                  : ftd623
Domains                   : cisco.com
DNS Servers               : 192.168.200.100
                            8.8.8.8
Management port           : 8305
IPv4 Default route
 Gateway                  : 10.62.148.129
==================[ management0 ]===================
State                     : Enabled
Channels                  : Management & Events
Mode                      : Non-Autonegotiation
MDI/MDIX                  : Auto/MDIX
MTU                       : 1500
MAC Address               : 70:DF:2F:18:D8:00
----------------------[ IPv4 ]----------------------
Configuration             : Manual
Address                   : 10.62.148.179
Netmask                   : 255.255.255.128
Broadcast                 : 10.62.148.255
----------------------[ IPv6 ]----------------------
Configuration             : Disabled
```

### `connect fxos`

```text
> connect fxos
Cisco Firepower Extensible Operating System (FX-OS) Software
...
firepower#
```

---

## FPR4100 CLI Verification

### Connect to the FTD Console

```text
FP4100# connect module 1 console
Firepower-module1> connect ftd
Connecting to ftd console... enter exit to return to bootCLI
>
>
```

### `show interface`

```text
> show interface
… output omitted …
Interface Ethernet1/3 "diagnostic", is up, line protocol is up
 Hardware is EtherSVI, BW 10000 Mbps, DLY 1000 usec
 MAC address 5897.bdb9.3e0e, MTU 1500
 IP address unassigned
 Traffic Statistics for "diagnostic":
 1304525 packets input, 63875339 bytes
 0 packets output, 0 bytes
 777914 packets dropped
 1 minute input rate 2 pkts/sec, 101 bytes/sec
 1 minute output rate 0 pkts/sec, 0 bytes/sec
 1 minute drop rate, 1 pkts/sec
 5 minute input rate 2 pkts/sec, 112 bytes/sec
 5 minute output rate 0 pkts/sec, 0 bytes/sec
 5 minute drop rate, 1 pkts/sec
 Management-only interface. Blocked 0 through-the-device packets
… output omitted …
>
```

---

## Removed as Non-CLI Reference Material

The refined file excludes the following source material because it does not add CLI command-reference value:

- Document contents/navigation block.
- Prerequisites and lab-component inventory.
- GUI-only navigation instructions.
- Screenshot OCR text and image artifacts.
- Hardware product photographs.
- FMC/FDM GUI screenshots.
- Deployment topology diagrams and scenario prose without CLI commands.
- Related-information/link lists.
- Duplicate or malformed OCR fragments.

