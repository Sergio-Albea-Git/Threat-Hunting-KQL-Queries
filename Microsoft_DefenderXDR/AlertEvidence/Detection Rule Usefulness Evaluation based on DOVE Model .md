**MITRE ATT&CK Technique(s)**

| Technique ID | Title |
| --- | --- |
| — | Operational / enrichment query (no single ATT&CK technique) |

**Author:** Sergio Albea (04/05/2026)

---

**Detection Rule Usefulness Evaluation based on DOVE Model**

**Description:** Creating multiple detections without reviewing them over time to ensure they’re still effective can easily turn them into pure noise, adding nothing but fatigue to our day-to-day incident analysis.
The DOVE Model (Detection Overlap & Value Evaluation) evaluates detections across four main dimensions (https://zenodo.org/records/20011459):

**1. Detection Type** :IOC-based detections tend to have a shorter lifecycle, current TI sources are collecting a huge number of indicators based on new attack or threats which present a higher duplication risk.
IOA-based detections focus on behaviors, have a longer lifecycle, provide higher unique value and requires extended time to create corresponding detection.

**2. System / Technology Coverage** :Mainstream technologies (e.g., Windows, M365, macOS) are heavily monitored and widely covered by SIEM platforms, increasing duplication probability.
Non-mainstream or custom systems offer less coverage and therefore provide opportunities for more unique detections.

**3. Threat Recency** :Older or well-known threats are widely documented and likely already covered by existing detections.
New or emerging threats are less likely to be covered, reducing duplication risk and increasing detection value.

**4. Source / Provider** :Built-in or native detections are already integrated into SIEM platforms and often overlap with custom logic.
Custom or third-party detections introduce tailored logic and reduce overlap probability.

The following KQL query can evaluate how useful are our current detections with the aim to detect alerts that are showing the same assets within the same hour, which indicates potential overlap.
Custom detections added in current SIEM or XDR solutions can easily turn from useful detections into noise, so analyzing their results is crucial.

```
AlertInfo
| join kind=inner AlertEvidence on AlertId
| extend DateHour=bin(Timestamp,1h)
| summarize Group_Alert_Tittles=make_set(Title),Different_Detection_Sources=make_set(DetectionSource),Number_Detection_Sources=dcount(DetectionSource) by DateHour,AccountUpn,EmailSubject,FileName, DeviceName, RemoteIP, RemoteUrl, Application
| where Number_Detection_Sources > 1 and Different_Detection_Sources contains "Custom detection" and (isnotempty(AccountUpn) or isnotempty(RemoteIP) or isnotempty(EmailSubject) or isnotempty(DeviceName) or isnotempty(RemoteUrl) or isnotempty(Application))
| order by Number_Detection_Sources desc
```
