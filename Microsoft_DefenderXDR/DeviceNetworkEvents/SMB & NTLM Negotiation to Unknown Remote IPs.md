**SMB & NTLM Negotiation to Unknown Remote IPs**

**Description**: NetworkSignatureInspected just means the network sensor saw and matched a signature (it inspected the packet) — it doesn’t mean the flow was blocked. That’s the problem.
If your machines are negotiating SMB or NTLM with unknown remote IPs, you’ve got a real risk on your hands: data leakage, credential relay, or worm-style propagation. SMB to the Internet is almost never legitimate; if you don’t recognize the remote IP, treat it as suspicious.

The KQL query includes multiple conditions to detect not only default connections on legacy (139) or modern (445) SMB ports, but also cases where SMB is running over non-standard ports (attempts to evade simple port-based detection). It also extracts the SMB negotiation state so you can spot repeated or incomplete negotiation attempts (useful to detect scanning, failed auths, or relay attempts).

```
DeviceNetworkEvents
| extend af = parse_json(AdditionalFields)
| extend SignatureName = tostring(af.SignatureName)
| extend SigMatched = tostring(af.SignatureMatchedContent)
| extend SamplePacket = tostring(af.SamplePacketContent)
| where isnotempty(RemoteIP)
 and (RemotePort in (139, 445) or LocalPort in(139,445) or SigMatched contains "%FESMB" or SigMatched contains "%FFSMB" or SigMatched contains "NTLMSSP" or SamplePacket contains "NTLMSSP")
| where not(ipv4_is_private(RemoteIP)) and isnotempty(SignatureName)  // only public IPv4
| extend geo_ip = tostring(geo_info_from_ip_address(RemoteIP).country)
| where isnotempty(geo_ip)
| extend Combined = strcat(SigMatched, " ", SamplePacket)
| extend MsgTypeNum = case(
 Combined contains "%01%00%00%00" or Combined contains "\x01\x00\x00\x00", 1,
 Combined contains "%02%00%00%00" or Combined contains "\x02\x00\x00\x00", 2,
 Combined contains "%03%00%00%00" or Combined contains "\x03\x00\x00\x00", 3,
 0)
| extend MsgType = case(
 MsgTypeNum == 1, "Type 1 = client initiates (Negotiate)",
 MsgTypeNum == 2, "Type 2 = server responds with Challenge",
 MsgTypeNum == 3, "Type 3 = client sends response with credentials",
 "Unknown / not extracted")
| summarize make_set(RemotePort),Distinct_ports=dcount(RemotePort), count() by DeviceName,LocalPort, InitiatingProcessFileName,geo_ip,RemoteIP, SignatureName,MsgType, ActionType
| order by Distinct_ports
```
