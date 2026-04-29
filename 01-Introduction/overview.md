# CyberPT HackCamp 2025 - Introduction

Welcome to the repository documenting my journey and learning experience at **Positive Technologies HackCamp**, held from **July 26 to August 10, 2025**. This prestigious two-week cybersecurity bootcamp brought together over 70 international professionals and enthusiasts to dive deep into real-world security scenarios, labs, and red-team/blue-team tasks guided by top experts from Positive Technologies and the broader cybersecurity community.

## About CyberED Labs

CyberED Labs is a practical, hands-on platform built to help participants gain **applied cybersecurity skills** by working on **realistic vulnerable systems** in a sandboxed environment. The core objective is to bridge the gap between **theoretical knowledge** and **real-world offensive/defensive operations**.

### Why CyberED Labs?

* Reinforce theoretical knowledge with practical application
* Improve problem-solving and critical thinking
* Understand real-world vulnerability exploitation and mitigation

### Key Features:

* **Automatic infrastructure deployment** (No manual VM/Container setup)
* **Wide range of curated labs**, developed by top infosec experts
* **Realistic attack simulations** in a safe environment
* **Time-limited lab instances** to optimize platform usage

## Labs from Day 0 - Getting Started

### 0. Kali Linux VM Access

If you lack a local Kali setup, CyberED offers a temporary [cloud VM](http://130.193.37.61?password=G2S4loXs-4B&autoconnect=true&resize=remote) (8-hour sessions). It supports browser, SSH, VNC, and RDP access: **Username**: `kali` and **Password**: `G2S4]loXs-4B`. This VM provides full access to all labs, with no VPN required.

### 1. Welcome VPN Check 
**Objective**: Validate your VPN setup
**Task**:
  1. Download VPN config
  2. Connect via OpenVPN
  3. Visit the lab IP address
  4. Retrieve the welcome flag

### 2. Vulnerable Linux Web Server 
**Objective**: Exploit a PHP-based arbitrary file upload vulnerability
**Steps**:
  1. Connect to the provided web interface
  2. Upload a PHP web shell (e.g., [simple-php-web-shell](https://github.com/artyuum/simple-php-web-shell))
  3. Use the shell to locate user SSH credentials in home directory notes
  4. Login as user via SSH
  5. Use `sudo` to read the root flag

## Summary

This introductory phase was focused on:
* Setting up lab infrastructure
* Validating connectivity via VPN
* Gaining shell access through web application vulnerabilities

These exercises laid the foundation for more advanced penetration testing and incident response techniques explored in subsequent modules. This practical approach helped reinforce OSINT, exploitation, enumeration, privilege escalation, and secure access concepts in real-world environments.