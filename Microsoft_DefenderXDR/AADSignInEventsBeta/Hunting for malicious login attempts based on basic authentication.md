**Hunting for malicious login attempts based on basic authentication**

**Description:**  This KQL Query helps to detect Basic authentication sign-in attempts using specific agents which are identified as risky and used by malicious actors.
The ROPC flow is considered insecure because it requires applications to handle user credentials directly, increasing the risk of credential theft. 
Microsoft discourages the use of ROPC and Basic Authentication in favor of more secure, modern authentication methods such as OAuth 2.0 with MFA and token-based authentication.


```
AADSignInEventsBeta
| where UserAgent  has "BAV2ROPC" or UserAgent has "AConsumerV2ROPC"
| where AuthenticationRequirement has "singleFactorAuthentication"
| distinct  Application, EndpointCall, ErrorCode, AuthenticationRequirement, UserAgent, ClientAppUsed, IPAddress , Country
```
