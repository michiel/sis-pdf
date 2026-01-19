
## Sample finding : URI present, but also contains JS

### sis\-4eec4b6b — URI present

- Surface: `Actions`
- Kind: `uri\_present`
- Severity: `Medium`
- Impact rating: `Medium`
- Confidence: `Probable`
- Objects: 8 0 obj
- Position: `doc:r0/action@8:0`

**Description**

Annotation action contains a URI target\.

**Runtime effect**

User may be redirected to external resources, enabling phishing or data exfiltration\.

**Payload**

```
javascript:confirm(2);
```

**Action chain**

Trigger: Finding \-\> Payload: string

**Impact**

URI actions can direct users to external resources, enabling phishing or data exfiltration\.

**Remediation**

Verify destination URLs\.

**Evidence**

- source=File offset=942 length=59 origin=\- note=Annotation /A
- source=File offset=967 length=4 origin=\- note=Key /URI
- source=File offset=972 length=26 origin=\- note=URI value
- source=File offset=972 length=26 origin=\- note=URI payload
- source=Decoded offset=0 length=22 origin=972\.\.998 note=Decoded payload preview=javascript:confirm\(2\);

**Metadata**

| Key | Value |
| --- | ----- |
| intent\.bucket | data\_exfiltration |
| intent\.confidence | Strong |
| payload\.decoded\_len | 22 |
| payload\.decoded\_preview | javascript:confirm\(2\); |
| payload\.preview | javascript:confirm\(2\); |
| payload\.ref\_chain | \- |
| payload\.type | string |
| position\.preview\.8:0 | dict Type=Annot Subtype=Link keys=/A,/Border,/Rect,/Subtype,/Type |

