
## Incorporate EICAR test files

## Content analysis should not run only against source, but also against reconstructed (e.g. divergent JS) payloads and data

PayloadsAllThePDFs/pdf-payloads on  main on ☁️  (ap-southeast-2) [X] took 4m32s 
❯ sis query --deep payload1.pdf
Loading PDF: payload1.pdf
PDF loaded. Enter queries (or 'help' for help, 'exit' to quit).

sis> findings
id           | kind                     | severity | confidence | title                             | objects                         
-------------+--------------------------+----------+------------+-----------------------------------+---------------------------------
sis-0ed040c5 | js_present               | High     | Strong     | JavaScript present                | [3 0]                           
sis-df7be1be | declared_filter_invalid  | High     | Probable   | Declared filters failed to decode | [9 0]                           
sis-37785380 | declared_filter_invalid  | High     | Probable   | Declared filters failed to decode | [12 0]                          
sis-d6b776ba | declared_filter_invalid  | High     | Probable   | Declared filters failed to decode | [13 0]                          
sis-54977316 | action_automatic_trigger | Medium   | Probable   | Automatic action trigger          | [1 0]                           
sis-f739ea92 | font.invalid_structure   | Medium   | Probable   | Font stream decode failed         | [11 0] [/BAAAAA+LiberationSerif]
sis-1e9bc6f0 | incremental_update_chain | Low      | Probable   | Incremental update chain present  | [xref]                          
sis-a2e4c597 | open_action_present      | Low      | Strong     | Document OpenAction present       | [1 0]                           
sis-18662394 | annotation_action_chain  | Low      | Probable   | Annotation action chain           | [8 0]                           
sis-82b061f4 | page_tree_fallback       | Low      | Heuristic  | Fallback /Pages root              | [page_tree]                     
sis-3bf77f70 | page_tree_mismatch       | Low      | Strong     | Orphaned page objects             | [page_tree] [6 0]               
sis-66666546 | content_html_payload     | Low      | Heuristic  | HTML-like payload in content      | [3 0]                           
sis-4eb95fb4 | xref_conflict            | Info     | Probable   | Multiple startxref entries        | [xref]                          
sis-a6065f81 | uri_present              | Info     | Probable   | URI present                       | [8 0]                           
sis-74cf521a | js_sandbox_exec          | Info     | Tentative  | JavaScript sandbox executed       | [3 0]
sis> explain sis-66666546
sis-666665463f0582f8997b20d31bbeb3ec4df9280771702f90d075f82e322556e7 - HTML-like payload in content
Content contains HTML or javascript-like sequences.
Severity: Low  Confidence: Heuristic

Evidence: source=File offset=424 length=205 note=HTML-like content
(app.alert\(1\); Object.getPrototypeOf(function*(){}).constructor = null; ((function*(){}).constructor("document.write('<script>confirm(document.cookie);</script><iframe src=https://14.rs>');"))().next();)
sis> 









