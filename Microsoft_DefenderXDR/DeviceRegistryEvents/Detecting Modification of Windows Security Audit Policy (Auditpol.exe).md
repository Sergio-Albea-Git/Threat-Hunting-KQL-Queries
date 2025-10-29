**Detecting Modification of Windows Security Audit Policy (Auditpol.exe)**

Monitoring the execution of auditpol.exe can be crutial to detect first-stage of a real attack because they will be shown as previous steps to obfuscate the next execution such a ransomware.

```
DeviceRegistryEvents
| where RegistryValueData startswith "auditpol"
```
