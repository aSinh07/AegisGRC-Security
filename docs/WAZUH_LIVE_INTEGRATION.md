# Wazuh → AegisGRC live telemetry

This integration is fail-closed. Registering a source does not mark it connected. Aegis reports CONNECTED only after an authenticated Wazuh alert is persisted.

## 1. Register the source
In AegisGRC select the organization, open Defensive Security → Live Defensive Telemetry, register a Wazuh source, and copy the one-time bearer token to the Wazuh manager host. Do not store the token in source control.

## 2. Wazuh custom integration
Create `/var/ossec/integrations/custom-aegis` on the Wazuh manager:

```python
#!/usr/bin/env python3
import json,os,sys,urllib.request
alert_path=sys.argv[1]
url=os.environ["AEGIS_WAZUH_WEBHOOK"]
token=os.environ["AEGIS_WAZUH_TOKEN"]
with open(alert_path,"rb") as f: body=f.read()
req=urllib.request.Request(url,data=body,headers={"Content-Type":"application/json","Authorization":"Bearer "+token},method="POST")
with urllib.request.urlopen(req,timeout=10) as response:
    if response.status not in (200,202): raise RuntimeError("Aegis HTTP "+str(response.status))
```

Make it executable and configure the Wazuh manager integration:

```xml
<integration>
  <name>custom-aegis</name>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

The environment variables must be supplied securely to the Wazuh manager service/process:
- `AEGIS_WAZUH_WEBHOOK`: the exact webhook displayed by Aegis
- `AEGIS_WAZUH_TOKEN`: the one-time bearer token displayed by Aegis

Restart the Wazuh manager only after validating its configuration with the Wazuh-supported configuration validation procedure for the installed version.

## 3. Acceptance proof
Generate an authorized endpoint event that Wazuh normally detects. Aegis must show:
1. source freshness CURRENT and status CONNECTED;
2. event_count increases;
3. the persisted event has an evidence SHA-256;
4. a Wazuh level >=7 alert creates a detection;
5. analyst escalation creates an Aegis incident;
6. the incident retains the originating detection evidence hash.

If any step fails, do not describe Wazuh monitoring as operational.
