# Calix AXOS Syslog Pack

Cribl Stream pack for parsing and enriching Calix AXOS syslog events. Supports all AXOS syslog facilities including command logs, alarm/event notifications, and category-specific messages with MITRE ATT&CK enrichment.

## Requirements

- Cribl Stream 4.0+
- Calix AXOS R25.x or compatible syslog source (RFC 3164)

## Syslog Facilities

AXOS uses LOCAL0-LOCAL7 syslog facilities, each mapped to a specific category:

- **LOCAL0** (code 16) - SECURITY: Security events
- **LOCAL1** (code 17) - ARC: Availability Redundancy Checkpointing alarms
- **LOCAL2** (code 18) - CONFIGURATION: Running configuration category
- **LOCAL3** (code 19) - DBCHANGE: Database change category
- **LOCAL4** (code 20) - GENERAL: General alarms
- **LOCAL5** (code 21) - ERPS: ERPS category
- **LOCAL6** (code 22) - COMMAND_LOG: User command logs
- **LOCAL7** (code 23) - ALARM_EVENT: Alarm and event notifications

## Pipelines

### Routes

Events are routed by facility to specialized pipelines:

1. **Calix Category Events (LOCAL0-LOCAL5)** - Category-specific enrichment
2. **Calix Command Logs (LOCAL6)** - Command log parsing (AT-CONFIG / AT-OPERATION)
3. **Calix Alarms/Events (LOCAL7)** - Alarm and event notification parsing
4. **Calix Default** - Catch-all for unmatched AXOS syslog events

### calix_category_enrich

Handles LOCAL0-LOCAL5 category facility events. Extracts AXOS bracket fields and message code, enriches with facility category from lookup, and sets dynamic sourcetype (calix:axos:<category>). Flags SECURITY category events.

### calix_command_log

Parses LOCAL6 command log events for both message types:

- **AT-CONFIG** - Configuration changes with xpath, old/new values, and session details
- **AT-OPERATION** - Status/show commands with session details

Extracts user, manager, IP, and session ID. Flags DENY results and config changes as security alerts. Enriches with MITRE ATT&CK mappings.

### calix_alarm

Parses LOCAL7 alarm/event notifications containing 17 comma-separated fields (Id, Syslog-Severity, Perceived-Severity, Name, Category, Cause, Details, Xpath, Address, Primary-element, Value, Verb, Session, Login, IpAddress, SrcManager, Secondary-element).

Enriches with:
- Severity mapping (perceived severity to syslog severity)
- Alarm definitions (security relevance flag)
- Event definitions (maskable flag)
- MITRE ATT&CK mappings

### calix_axos_main

Default pipeline for all AXOS syslog events. Extracts bracket fields [shelf][slot][A|S][pid] [facility_code], message code, and appname. Enriches with facility category lookup and sets sourcetype/index.

## Lookups

- **calix_facility_map.csv** - Maps facility codes (16-23) to category names and descriptions
- **calix_severity_map.csv** - Maps AXOS perceived severity to syslog severity values
- **calix_alarm_definitions.csv** - Alarm definitions with security relevance flags (51 alarms)
- **calix_event_definitions.csv** - Event definitions with security relevance and maskable flags (66 events)
- **calix_security_events.csv** - MITRE ATT&CK tactic and technique mappings (17 events)

## Extracted Fields

### Common Fields (all pipelines)

- **shelf_id** - Shelf identifier
- **slot_id** - Slot identifier
- **controller_state** - Active (A) or Standby (S)
- **process_id** - Process identifier
- **facility_code** - Numeric facility code (16-23)
- **axos_category** - Resolved category name
- **facility_name** - Resolved facility name (LOCAL0-LOCAL7)
- **appname** - Application name from syslog header
- **sourcetype** - Cribl sourcetype

### Command Log Fields (LOCAL6)

- **message_code** - Message identifier (e.g., DBCMD.DBA.1)
- **message_type** - AT-CONFIG or AT-OPERATION
- **action_type** - Resolved action type
- **status** - COMPLD (success) or DENY (denied)
- **session_user** - User who issued the command
- **session_manager** - Management interface (cli, netconf, ewi)
- **session_ip** - Source IP address
- **session_id** - Session identifier
- **config_verb** - Configuration verb (for AT-CONFIG)
- **config_xpath** - Configuration path (for AT-CONFIG)
- **old_value** - Previous value (for AT-CONFIG)
- **new_value** - New value (for AT-CONFIG)
- **mitre_tactic** - MITRE ATT&CK tactic
- **mitre_technique_id** - MITRE ATT&CK technique ID
- **mitre_technique_name** - MITRE ATT&CK technique name
- **security_alert** - Boolean flag for security-relevant events

### Alarm/Event Fields (LOCAL7)

- **alarm_id** - Alarm identifier
- **syslog_severity** - Numeric syslog severity
- **perceived_severity** - AXOS severity (CRITICAL, MAJOR, MINOR, WARNING, INFO, CLEAR)
- **alarm_name** - Alarm or event name
- **alarm_category** - Alarm category
- **alarm_cause** - Alarm cause description
- **alarm_details** - Alarm detail text
- **alarm_xpath** - Affected resource path
- **alarm_address** - Address information
- **primary_element** - Primary element identifier
- **secondary_element** - Secondary element identifier
- **alarm_verb** - Alarm verb
- **alarm_login** - Associated login
- **alarm_ip** - Associated IP address
- **alarm_src_manager** - Source manager
- **security_relevant** - Boolean flag from alarm definitions lookup
- **maskable** - Boolean flag from event definitions lookup
- **syslog_severity_name** - Resolved syslog severity name
- **mitre_tactic** - MITRE ATT&CK tactic
- **mitre_technique_id** - MITRE ATT&CK technique ID
- **mitre_technique_name** - MITRE ATT&CK technique name
- **security_alert** - Boolean flag for security-relevant events

## Release Notes

### 1.0.0

- Initial release
- Parsing for all AXOS syslog facilities (LOCAL0-LOCAL7)
- Command log parsing (AT-CONFIG and AT-OPERATION)
- Alarm/event notification parsing with 17-field extraction
- Facility, severity, alarm, event, and security event lookups
- MITRE ATT&CK enrichment for security-relevant events
