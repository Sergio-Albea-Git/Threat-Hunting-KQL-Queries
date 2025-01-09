**𝐈𝐯𝐚𝐧𝐭𝐢 𝐕𝐮𝐥𝐧𝐞𝐫𝐚𝐛𝐢𝐥𝐢𝐭𝐢𝐞𝐬 𝐂𝐕𝐄-𝟐𝟎𝟐𝟓-𝟎𝟐𝟖𝟐 (𝟗.𝟎 Critical 𝟎-𝐃𝐚𝐲 𝐕𝐮𝐥𝐧.) 𝐚𝐧𝐝 𝐂𝐕𝐄-𝟐𝟎𝟐𝟓-𝟎𝟐𝟖𝟑 (𝟕.𝟎 High)**

𝐂𝐕𝐄-𝟐𝟎𝟐𝟓-𝟎𝟐𝟖𝟐  9.0 (Critical) 
A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution. 

𝐂𝐕𝐄-𝟐𝟎𝟐𝟓-𝟎𝟐𝟖𝟑 7.0 (High)
A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a local authenticated attacker to escalate their privileges. 

This query detect previous versions of Ivanti Connect Secure 22.7R2.5 to be updated ASAP using the patch provided by Ivanti.

**Ivanti Secure Access Client**:
ivanti_secure_access = VPN client Only
pulse_application_launcher = VPN client with launcher (needed for MFA login with mini browser in client )


```
DeviceTvmSoftwareInventory
| where SoftwareVendor has "ivanti"
| extend SoftwareVersionD =replace_string(SoftwareVersion,".","")
| extend firstDigits = toint(substring(SoftwareVersionD,0,5))
| where firstDigits < 22731 and (SoftwareName startswith "ivanti_secure_access" or SoftwareName has "pulse_application_launcher" )
| distinct DeviceName,SoftwareVersion, SoftwareName, SoftwareVendor ```
