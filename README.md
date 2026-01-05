# Config Manager REST API

<p align="center">
  <img src="docs/config-manager-rest-api.png" alt="Config Manager REST API" width="900">
</p>


Eine robuste, systemnahe REST API zur **kontrollierten Verwaltung von Konfigurationsdateien** auf Servern.
Das Projekt richtet sich an Administratoren, Automations-Loesungen und technische Plattformen, die Konfigurationen zentral lesen, schreiben und versionieren muessen, ohne ein Web-UI oder interaktive Bedienung.

Der Fokus liegt bewusst auf:
- technischer Klarheit
- sicherem Default-Verhalten
- nachvollziehbaren Aktionen
- stabiler Integration in bestehende Systeme

Kein UI. Kein Framework-Zirkus. Reine API.

---

## Motivation

In vielen Umgebungen werden Konfigurationsdateien weiterhin direkt auf dem System gepflegt, waehrend Steuerung, Deployment und Monitoring extern stattfinden.
Diese API schliesst genau diese Luecke.

Sie ermoeglicht:
- kontrollierten Remote-Zugriff auf Konfigurationsdateien
- reproduzierbare Aenderungen ueber HTTP
- saubere Integration in CI/CD, Orchestrierung und Admin-Tools
- klare Trennung zwischen Steuerung und Ausfuehrung

---

## Eigenschaften

- Reine REST API (JSON)
- Lesen und Schreiben von Konfigurationsdateien
- Definierte Aktionen pro Konfiguration
- Optionaler Backup-Mechanismus
- Sauberes Fehler- und Statusmodell
- Systemnahe Ausfuehrung (systemctl, Scripts)
- Kein Zustand im Serverprozess

---

## Architektur

- Sprache: Perl
- Framework: Mojolicious::Lite
- API-Stil: REST, JSON
- Nebenlaeufigkeit: Mojo::IOLoop + Subprocess
- Logging: Mojo::Log
- Laufzeit: systemd, VM oder Container

Die API ist zustandslos und blockiert keine Worker bei Systemoperationen.

---

## Sicherheit

Sicherheit ist kein Add-on, sondern Grundannahme:

- IP-basierte Zugriffskontrolle (CIDR)
- Optionaler API-Token (Header oder Bearer)
- Strikte Pfad-Kanonisierung
- Kein Directory Traversal
- Keine Symlink-Folgen
- Whitelist-basierte Aktionen
- Keine impliziten Defaults

Alle sicherheitsrelevanten Ereignisse werden geloggt.

---

## Vergleich: Config-Manager vs. andere Lösungen

| Feature | **Config-Manager (REST)** | Ansible / Salt | Server-Panels (Cockpit/Webmin) | Eigene Bash-Skripte |
| :--- | :--- | :--- | :--- | :--- |
| **Modus** | **Native REST-API** (Sofort) | SSH / Push (Langsam) | Web-Oberfläche (Schwer) | Manuell / Skript |
| **Architektur** | **Non-blocking (Async Mojo)** | Blockierendes Python | Blockierend (PHP/JS) | Blockierend |
| **Sicherheit** | **Mehrstufig** (Path-Guard, IP-ACL, Token) | SSH-Key basiert | Benutzer / Passwort | Root-SSH (Hohes Risiko) |
| **Datensicherheit** | **Atomares Schreiben** + Backups | Modul-abhängig | Meist direktes Schreiben | Keine |
| **Fokus** | **Operativer Betrieb (Ops)** | Einmalige Provisionierung | Manuelle Verwaltung | Ad-hoc Korrekturen |
| **API-Antwort** | **Strukturiertes JSON** | CLI-Logs / Text | Web-Interface | Roher Text (Strings) |
| **Footprint** | **Minimal** (Natives Perl) | Mittel (Python Stack) | Hoch (Ganzer Daemon) | Null (aber unsicher) |
| **CI/CD-Integration**| **Exzellent** (Nativ JSON) | Gut (über CLI-Wrapper) | Nicht für CI gedacht | Schwer zu parsen |

---

### Einordnung & Einsatzzweck

Der **Config-Manager REST** ist eine leichtgewichtige, gehärtete Middleware für den **automatisierten IT-Betrieb**. Während Tools wie Ansible hervorragend für das initiale Aufsetzen (*Provisioning*) eines Servers geeignet sind, füllt der Config-Manager die Lücke im täglichen Betriebszyklus:

1.  **Sichere Middleware:** Er bietet eine "kontrollierte Sandbox" für Automatisierung-Bots und CI/CD-Pipelines. Anstatt vollen Root-SSH-Zugriff zu gewähren, werden nur explizit definierte Dateien und Aktionen über eine gesicherte API freigegeben.
2.  **Infrastructure as Code (IaC) Endpunkt:** Er fungiert als finaler programmierbarer Endpunkt für Konfigurationsänderungen und stellt sicher, dass jeder Schreibvorgang atomar erfolgt und automatisch gesichert wird.
3.  **Resilienter Betrieb:** Durch die Integration von "Settle-Time"-Logik und anschließender Status-Verifizierung wird sichergestellt, dass Dienste nach einer Änderung nicht nur "neu gestartet" wurden, sondern tatsächlich funktionsfähig sind.

### Warum nicht einfach Ansible nutzen?
Ansible ist ein mächtiger Orchestrator, aber oft zu träge für häufige, API-gesteuerte Konfigurations-Updates in Echtzeit. Der Config-Manager ist ein **"Always-on"-Micro-Agent**, der in Millisekunden reagiert und native Sicherheitsfeatures wie den `Path-Guard` (verhindert das Ausbrechen aus Verzeichnissen) und `Atomares Schreiben` (verhindert korrupte Dateien) bietet, die in eigenen Skripten oder generischen Tools oft fehlen.

---

## Installation

~~~bash
git clone https://github.com/hec1976/config-manager-rest-api.git
cd config-manager-rest-api
chmod +x config-manager.pl
~~~

Abhaengigkeiten installieren:

~~~bash
cpanm Mojolicious
~~~

---

## Betrieb

Die API wird als normaler Prozess gestartet und laesst sich problemlos als systemd-Service betreiben.

~~~bash
./config-manager.pl
~~~

Nach dem Start stellt die API ihre Endpunkte ueber HTTP bereit.

---

## Schnittstelle

Die API stellt ausschliesslich JSON-Endpunkte bereit.
Alle Antworten sind explizit und maschinenlesbar.

Typische Operationen:
- Auflisten verfuegbarer Konfigurationen
- Lesen einer Konfiguration
- Schreiben einer Konfiguration
- Ausfuehren definierter Aktionen
- Auflisten und Wiederherstellen von Backups
- Health-Check

Die konkrete Auspraegung erfolgt bewusst konfigurationsgetrieben und ist nicht Teil dieser README.

---

## Logging und Nachvollziehbarkeit

- Jeder Request erhaelt eine Request-ID
- Laufzeiten werden gemessen
- Rueckgabecodes werden geloggt
- Fehler werden strukturiert ausgegeben

Das ermoeglicht saubere Analyse und Auditierung.

---

## Abgrenzung

Dieses Projekt ist **kein**:
- Konfigurationsmanagement-System (wie Ansible, Puppet)
- UI-Tool
- State-Engine
- Policy-Framework

Es ist ein **technischer Baustein**, der bewusst klein gehalten ist.

---



