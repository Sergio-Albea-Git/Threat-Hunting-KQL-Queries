**[IA] - Applying Shanon Entropy to SenderDomains via Kusto**

#### MITRE ATT&CK Technique(s)

| Technique ID | Title    |
| ---  | --- |
| T1566.002 | Phishing: Spearphishing Link  |


| Author | Sergio Albea (12/02/2026)   |
| ---  | --- |

**Description:** TDomains that introduce substitutions, extra characters, or randomness (e.g., micr0soft, paypa1-secure) tend to have higher entropy than the original brand name. This increase in entropy is a useful signal for detecting typosquatting and brand impersonation attempts in phishing campaigns.

```
//Sergio Albea 12-02-2026 ©
// Keyword focus (optional narrowing). From an entropy perspective, this step prioritizes domains that impersonate well-known, low-entropy (human-readable) brand names that attackers commonly abuse.
// ============================================================
let Keywords=dynamic(["microsoft","office","sbb","poste","univer","payment","portal","sign","students","brands","invoice","sharepoint","onedrive","linkedin","google"]);
// ==============================
// Configuration / thresholds
// ==============================
// LookbackTop  : Used to learn what "normal" looks like (low entropy, stable domains)
// LookbackHunt : Window where we search for deviations (higher entropy lookalikes)
let LookbackTop=15d;
let LookbackHunt=15d;
let TopN=2000;
let MinMsgs=1;
let MaxUrls=200;
// ==============================
// Helper functions
// ==============================
// Normalization reduces artificial entropy introduced by casing or formatting differences
let Normalize=(s:string){tolower(trim(" ",coalesce(s,"")))};   
// RootDomain extraction isolates the registrable domain, which is the meaningful unit when evaluating entropy and impersonation
let RootDomain=(d:string){
    let h=Normalize(d);
    let p=split(h,".");
    let n=array_length(p);
    iif(n>=2,strcat(p[n-2],".",p[n-1]),h)
};
// DomainLabel extracts the core label attackers manipulate. Shannon entropy is implicitly evaluated on this string.
let DomainLabel=(d:string){
    let h=Normalize(d);
    let p=split(h,".");
    let n=array_length(p);
    iif(n>=2,tostring(p[n-2]),h)
};
// ==============================
// Base dataset: inbound sender domains
// ==============================
// This dataset represents observed sender domains.
// Legitimate domains tend to have:
//  - Low entropy
//  - Predictable character distribution
//  - Stable appearance over time
let Base= EmailEvents
| where Timestamp>=ago(LookbackHunt)
| where EmailDirection=="Inbound"
| where isnotempty(SenderFromDomain)
| extend Root=RootDomain(SenderFromDomain)
| extend Label=DomainLabel(Root)
// Short labels are excluded because entropy comparison
// becomes unreliable on very small strings
| where strlen(Label)>=6;
// ==============================
// Build baseline list of common sender domain labels
// ==============================
// This baseline approximates *low-entropy reference strings*. These are domains frequently seen, human-readable, and stable. In Shannon terms: predictable symbol distribution over time.
let TopList=toscalar(
    Base
    | where Timestamp>=ago(LookbackTop)
    | summarize TopHits=count() by TopLabel=Label
    | top TopN by TopHits desc
    | extend TopLen=strlen(TopLabel)
    | extend TopPrefix=substring(TopLabel,0,3)
    | extend TopSuffix=substring(TopLabel,TopLen-3,3)
    | summarize L=make_list(
        pack("TopLabel",TopLabel,"TopLen",TopLen,"TopPrefix",TopPrefix,"TopSuffix",TopSuffix,"TopHits",TopHits),
        TopN )
    | project L);
// ==============================
// Identify suspicious look-alike sender domains
// ==============================
// This section acts as a *Shannon entropy proxy* without computing entropy directly.
//
// Instead of H(X), we approximate increased entropy by detecting:
//  1) Structural similarity to a low-entropy baseline (same prefix/suffix)
//  2) Increased character randomness (digits, symbols, hyphens)
//  3) Length variation suggesting mutation rather than coincidence
let SuspiciousDomains=materialize(
    Base
    | summarize CandidateHits=count(),ExampleDomains=make_set(Root,5) by CandLabel=Label
    | where CandidateHits>=MinMsgs
    // Length and anchors define the expected structure of the low-entropy string
    | extend CandLen=strlen(CandLabel)
    | extend CandPrefix=substring(CandLabel,0,3)
    | extend CandSuffix=substring(CandLabel,CandLen-3,3)
    // Digits and symbols increase entropy by expanding the character alphabet
    | extend DigitCount=strlen(replace_regex(CandLabel,@"[^0-9]",""))
    | extend SymbolCount=CandLen - strlen(replace_regex(CandLabel,@"[a-z0-9]",""))
    | extend TopList=TopList
    | mv-expand TopList
    | extend TopLabel=tostring(TopList.TopLabel),
             TopLen=toint(TopList.TopLen),
             TopPrefix=tostring(TopList.TopPrefix),
             TopSuffix=tostring(TopList.TopSuffix),
             TopHits=toint(TopList.TopHits)
    | where CandLabel!=TopLabel  // Exact matches are excluded (entropy remains unchanged)
    | where CandPrefix==TopPrefix and CandSuffix==TopSuffix     // Same prefix/suffix implies impersonation, not coincidence
    | where CandLen>=TopLen-2 and CandLen<=TopLen+6     // Length drift indicates mutation while staying visually similar
    // Avoid trivial concatenations that do not significantly increase entropy
    | where not(CandLabel startswith TopLabel) and not(CandLabel endswith TopLabel)
    | where DigitCount>0 or SymbolCount>0     // Require entropy-increasing signals
    // SuspicionScore approximates normalized entropy increase:
    // higher symbol diversity per character = higher disorder
    | extend SuspicionScore=
        (todouble(DigitCount)+todouble(SymbolCount))
        / todouble(iif(CandLen==0,1,CandLen))
    | project LegitSenderDomain=TopLabel,
              LookalikeSenderDomain=CandLabel,
              TopHits,
              CandidateHits,
              DigitCount,
              SymbolCount,
              SuspicionScore
);
// ==============================
// Collect URLs per email (via NetworkMessageId)
// ==============================
let UrlByMsg=
EmailUrlInfo
| where Timestamp>=ago(LookbackHunt)
| where isnotempty(Url)
| summarize Urls=make_set(Url,MaxUrls) by NetworkMessageId;
// ==============================
// Final aggregation (EED-compatible output)
// ==============================
Base
| project ReportId,NetworkMessageId,SenderFromDomain,Root,Label,Timestamp,DeliveryLocation,ThreatTypes
| join kind=inner (
    SuspiciousDomains
    | project LookalikeSenderDomain,LegitSenderDomain,SuspicionScore
) on $left.Label==$right.LookalikeSenderDomain
| join kind=leftouter UrlByMsg on NetworkMessageId
| mv-apply U=Urls on (
    where tostring(U) contains LookalikeSenderDomain
    | summarize FilteredUrls=make_set(tostring(U),5)
)
| summarize
    Timestamp=min(Timestamp),
    ReportId=any(ReportId),
    Messages=count(),
    ExampleDomains=make_set(SenderFromDomain,5),
    Urls=make_set(FilteredUrls,5),
    DeliveryLocations=make_set(DeliveryLocation,5),
    ThreatTypesSet=make_set(ThreatTypes,5)
    by LegitSenderDomain,LookalikeSenderDomain,SuspicionScore
// ==============================
// Optional tuning: brand relevance OR entropy escalation
// ==============================
// match > 0  : Brand/keyword-based impersonation (semantic confidence)
// SuspicionScore > 1 : High-entropy mutation even without brand keywords
| extend LSD=tolower(tostring(LegitSenderDomain))
| mv-apply k=Keywords on (where LSD contains tostring(k) | summarize match=count())
| where match>0 or SuspicionScore > 1
| extend Timestamp=Timestamp,ReportId=tostring(ReportId)
```
