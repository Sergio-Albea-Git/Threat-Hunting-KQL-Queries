**Monitor Exclusion into Conditional Access Policies**

**Description:**  This KQL Query helps to keep an eye on accounts that are being excluded from Conditional Access (CA) policies which they should be blocked by it and which specific field triggered the CA detection and got them excluded.

The aim of this case is to identify:

- Spot CA policies with a high number of exclusions.
- Find exclusions that don’t make sense, like skipping MFA when it’s mandatory for privileged accounts.
- Catch new exclusions that might not have been approved.
- Check how exclusions are actually working (e.g., excluding a device is fine, but if it’s connecting from risky countries or open networks, that’s a problem—hopefully, other CA policies cover this).
- Identify unexpected exclusions, which could mean an attacker got in and excluded themselves to bypass CA controls
  
```
AADSignInEventsBeta
| extend ca = todynamic(tostring(ConditionalAccessPolicies))
| mv-expand Policies = parse_json(ConditionalAccessPolicies)
| extend PolicyName = tostring(Policies.displayName),
 PolicyId = tostring(Policies.id),
 PolicyResult = tostring(Policies.result),
 EnforcedGrantControls = tostring(Policies.enforcedGrantControls),
 EnforcedSessionControls = tostring(Policies.enforcedSessionControls),
 Excluded = tostring(Policies.excludeRulesSatisfied)
| mv-expand CA_field_excluded = parse_json(Excluded)
| extend CA_field_reason_excluded = tostring(todynamic(CA_field_excluded.ruleSatisfied))
| where Excluded contains "conditional" and EnforcedGrantControls has '["Block"]'
| summarize total_CA_excluded_times= count() by AccountDisplayName,AccountUpn,Country,CA_field_reason_excluded ,EnforcedGrantControls, PolicyName, PolicyId
```
