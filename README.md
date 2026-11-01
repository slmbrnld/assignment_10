# Nmap Scan Detection with Zeek

This repository contains two Zeek scripts developed for the course Network Security. 

## Detection Scripts

**TCP SYN Scan (syn-scan.zeek)** - Detects potential Nmap -sS scans by identifying TCP connections where a SYN was observed without an ACK from the source.

**TCP Connect Scan (tcp-connect-scan.zeek)** - Detects potential Nmap -sT scans by identifying TCP connections with a completed three-way handshake.
