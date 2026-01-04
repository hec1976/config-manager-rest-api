# Config Manager REST API

## Überblick

Der **Config Manager** ist ein gehärteter REST-basierter Konfigurationsdienst auf Basis von **Mojolicious::Lite**.
Er dient zur zentralen Verwaltung von Konfigurationsdateien, inklusive Lesen, Schreiben, Backup, Restore und dem Ausführen definierter Aktionen wie systemctl-Befehle oder Skripte.

Der Dienst ist für produktive Linux-Systeme ausgelegt und legt grossen Wert auf Sicherheit, Nachvollziehbarkeit und atomare Dateizugriffe.

Version: 1.7.3

---

## Features

- REST API zur Verwaltung von Konfigurationsdateien
- Atomisches Schreiben mit Fallback
- Automatische Backup-Erstellung mit Versionslimit
- Wiederherstellung einzelner Backup-Versionen
- Definierte Aktionen pro Konfiguration
- systemctl Integration mit Timeout und Subprocess
- Promise-basierte, nicht blockierende Ausführung
- Token-basierte Authentisierung
- IP-basierte Zugriffsbeschraenkung
- Pfad-Whitelist mit optionalem Audit-Modus
- Optionales Setzen von User, Group und Mode
- CORS-Unterstuetzung
- Umfangreiches Logging

---

## Voraussetzungen

- Linux mit systemd
- Perl >= 5.24 empfohlen
- Mojolicious
- Benötigte Perl-Module:
  - Mojolicious::Lite
  - Mojo::File
  - Mojo::Promise
  - Mojo::JSON
  - Mojo::Date
  - Net::CIDR
  - Text::ParseWords

---

## Verzeichnisstruktur

```bash
config-manager/
├── config-manager.pl
├── global.json
├── configs.json
├── backup/
├── tmp/
└── logs/
```
---

## Konfigurationsdateien

### global.json (Beispiel)

```bash
{
  "listen": "127.0.0.1:3000",
  "api_token": "SEHR_GEHEIM",
  "allowed_ips": ["127.0.0.1/32"],
  "allowed_roots": ["/etc", "/opt"],
  "logfile": "/var/log/config-manager.log",
  "backupDir": "./backup",
  "tmpDir": "./tmp",
  "maxBackups": 10,
  "path_guard": "on",
  "apply_meta": 0
}
```
---

### configs.json (Beispiel)

```bash
{
  "postfix_main": {
    "path": "/etc/postfix/main.cf",
    "service": "postfix",
    "category": "mail",
    "actions": {
      "reload": [],
      "restart": []
    },
    "user": "root",
    "group": "root",
    "mode": "0644"
  }
}
```
---

## REST API Endpunkte

```bash
GET    /
GET    /configs
GET    /config/:name
POST   /config/:name
GET    /backups/:name
GET    /backupcontent/:name/:file
POST   /restore/:name/:file
POST   /action/:name/:cmd
GET    /health
```
---

## Authentisierung

Zugriff erfolgt ueber:

- Header: X-API-Token
- oder Authorization: Bearer <token>

---

## Backups

- Automatische Erstellung vor jedem Schreiben
- Format: YYYYMMDD_HHMMSS
- Maximale Anzahl ueber maxBackups konfigurierbar
- Alte Backups werden automatisch entfernt

---

## Sicherheit

- Keine Symlink-Zugriffe
- Pfad-Whitelist mit path_guard
- Kritische systemctl Befehle gesperrt
- Argument-Validierung
- systemctl mit Timeout
- Kein Blockieren des Eventloops

---

## Starten

perl config-manager.pl daemon

---

## Lizenz

MIT License
