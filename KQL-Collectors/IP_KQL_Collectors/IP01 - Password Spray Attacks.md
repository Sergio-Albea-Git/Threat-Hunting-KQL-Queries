**IP01- Password Spray Attacks**

**Description:**  Collecting IPs recognized and tagged by DefenderXDR as malicious and related to Password Spray Attacks.
```
{
 "Query": " AlertEvidence | where Timestamp > ago(1d) and  Title contains 'Password Spray' and isnotempty(RemoteIP) | extend parsed = parse_json(AdditionalFields) | extend CountryCode = tostring(parsed.Location.CountryCode), ASN = tostring(parsed.Location.Asn) | extend Time_ = format_datetime( Timestamp, 'dd-MM-yyyy') |extend rawHash = substring(tostring(hash_sha256(strcat(1, tostring(rand())))), 0, 32) | extend GeneratedUUID = strcat( substring(rawHash, 0, 8), '-', substring(rawHash, 8, 4), '-', substring(rawHash, 12, 4), '-', substring(rawHash, 16, 4), '-', substring(rawHash, 20, 12) ) | distinct Time_,ASN, AttackTechniques,Title, RemoteIP, CountryCode,GeneratedUUID "
}
```
