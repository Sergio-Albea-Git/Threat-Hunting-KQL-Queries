**Detecting Windows Security Event Logs Cleaned**

**Description:**  This KQL query below will help you detect cases where Windows Security Event Logs, has been removed directly using Event Viewer.
Among the potential mitigations and associated threats, we have:

𝐓𝐡𝐫𝐞𝐚𝐭 𝐦𝐢𝐭𝐢𝐠𝐚𝐭𝐢𝐨𝐧𝐬:
– Restrict access to Device Logs
– Audit access to Device Logs
– Backup Device Logs

𝐓𝐡𝐫𝐞𝐚𝐭𝐬 𝐚𝐬𝐬𝐨𝐜𝐢𝐚𝐭𝐞𝐝:
– Lost of non-reputation evidence
– Lack of visibility over malicious activities
– Regulatory Non-Compliance

```
DeviceEvents
| where ActionType has "SecurityLogCleared"
```
