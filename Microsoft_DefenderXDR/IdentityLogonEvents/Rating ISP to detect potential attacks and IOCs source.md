**Rating ISP to detect potential attacks and IOCs sources**

**Description:** Researching about how to classify ISP based on different factors, I created a query to ISP based on sign-in attempts. It includes, how to monitor or react against possible attacks from a same ISP, use ISP as a new type of IOC (further than IPs, URL, Domains and FileHashes) and others ones explained in detail.

```
IdentityLogonEvents
| where Timestamp > ago(30d)
| summarize Different_IPs=make_set(IPAddress), Total_different_IPs=dcount(IPAddress) ,Total_sign_attempts = count(), Suspicious_Sign_attempt = countif((ActionType has "OldPassword") or (FailureReason has "WrongPassword") or ( FailureReason has "validating credentials due to invalid username or password.") or ( FailureReason has "The account is locked, you've tried to sign in too many times with an incorrect user ID or password.") or (FailureReason has "Authentication failed.") or (FailureReason has "UnknownUser") or ( FailureReason has "The user account is disabled." )),
 Success_Sign_attempt = count( ActionType has "LogonSuccess"),
 Issues_Sign_attempt = countif((FailureReason has "The session is not valid due to password expiration or recent password change.") or ( FailureReason has "General failure")) by ISP, Location
| extend SuspiciousRatio = Suspicious_Sign_attempt * 1.0 / Total_sign_attempts, ValidRatio = Success_Sign_attempt * 1.0 / Total_sign_attempts, IssuesRatio = Issues_Sign_attempt * 1.0 / Total_sign_attempts
| extend SuspiciousPercentage = SuspiciousRatio * 100, ValidPercentage = ValidRatio * 100, IssuesPercentatge = IssuesRatio * 100
| order by SuspiciousPercentage
```
