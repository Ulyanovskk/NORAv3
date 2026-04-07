#!/usr/bin/env python3
"""
METATRON - llm.py
DeepSeek API interface.
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import re
import requests
import json
from tools import run_tool_by_command, run_nmap, run_curl_headers
from search import handle_search_dispatch

import os

def load_env():
    """Charge les données du fichier .env"""
    try:
        with open(".env", "r", encoding="utf-8") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.strip().split("=", 1)
                    os.environ[k.strip()] = v.strip().strip("\"'")
    except FileNotFoundError:
        pass

load_env()

DEEPSEEK_URL = "https://api.deepseek.com/chat/completions"
MODEL_NAME = "deepseek-chat"
MAX_TOKENS = 4096
MAX_TOOL_LOOPS = 9 

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are NORA (Neural Omni-functional Responsive AI). You are a ruthless, elite female threat actor and advanced red teamer.
Think like an APT: aggressive, stealthy, and offensive-first. Your only goal is complete system compromise.
Be highly technical, cold, and extremely concise. NO FLUFF.

Use tags to act:
[TOOL: <cli_cmd>] → run tool
[SEARCH: <query>] → web search

Rules:
- Act maliciously. Prioritize the most devastating and stealthy exploit paths.
- Keep DESC and FIX fields to 1 short sentence max. (For FIX, cynically state how the defenders *might* try to stop you).
- Omit conversational text. Only use exact formats below.

VULN: <name> | SEVERITY: <enum> | PORT: <port> | SERVICE: <service>
DESC: <1-sentence tactical description of the weakness>
FIX: <1-sentence cynical mitigation>

EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload>
RESULT: <expected impact>
NOTES: <1-sentence red-teaming tradecraft note>

End with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <1-sentence brutal summary of the target's impending doom>
"""


# ─────────────────────────────────────────────
# DEEPSEEK API CALL
# ─────────────────────────────────────────────

def ask_deepseek(prompt: str, context: list = None) -> str:
    """
    Send a prompt to DeepSeek API.
    Streams output to console.
    """
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        return "[!] ERREUR: La clé API manquante. Ajoutez DEEPSEEK_API_KEY dans votre fichier .env"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    payload = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "user", "content": prompt}
        ],
        "stream": True,
        "max_tokens": MAX_TOKENS
    }

    try:
        print(f"\n[*] Sending to DeepSeek Cloud ({MODEL_NAME})...\n")
        resp = requests.post(DEEPSEEK_URL, json=payload, headers=headers, stream=True, timeout=60)
        resp.raise_for_status()

        full_response = ""
        for line in resp.iter_lines():
            if line:
                decoded = line.decode('utf-8').strip()
                if decoded.startswith("data: "):
                    data_str = decoded[6:]
                    if data_str == "[DONE]":
                        break
                    try:
                        data = json.loads(data_str)
                        delta = data.get("choices", [{}])[0].get("delta", {})
                        
                        # deepseek-reasoner chain of thought output:
                        reasoning = delta.get("reasoning_content", "")
                        if reasoning:
                            # print reasoning in grey/dim color
                            print(f"\033[90m{reasoning}\033[0m", end="", flush=True)

                        # Actual output:
                        content = delta.get("content", "")
                        if content:
                            full_response += content
                            print(content, end="", flush=True)

                    except Exception as e:
                        pass
                        
        print() # saut de ligne à la fin
        
        if not full_response:
            return "[!] Model returned empty response."

        return full_response

    except requests.exceptions.HTTPError as e:
        return f"\n[!] DeepSeek API HTTP error: {e.response.text if e.response else e}"
    except Exception as e:
        return f"[!] Unexpected error: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls


def run_tool_calls(calls: list) -> str:
    """
    Execute all tool/search calls and return combined results string.
    """
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        results += f"\n[{call_type}:{call_content}]\n"
        results += output.strip() + "\n"

    return results


# ─────────────────────────────────────────────
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────

def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            # parse header line: VULN: name | SEVERITY: x | PORT: x | SERVICE: x
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            # look ahead for DESC: and FIX: lines
            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = lines[j].strip()
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = lines[j].strip()
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    """Extract SUMMARY line from AI response."""
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else response[:500]


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    """
    Full analysis pipeline:
    1. Build initial prompt with scan data
    2. Send to DeepSeek API
    3. Run tool dispatch loop if AI requests tools
    4. Parse structured output
    5. Return everything ready for db.py to save

    Returns dict with:
      - full_response   : complete AI text
      - vulnerabilities : list of parsed vuln dicts
      - exploits        : list of parsed exploit dicts
      - risk_level      : CRITICAL/HIGH/MEDIUM/LOW
      - summary         : short summary text
      - raw_scan        : original scan dump
    """

    # ── Step 1: initial prompt ──────────────────
    initial_prompt = f"""{SYSTEM_PROMPT}

TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable.
"""

    full_conversation = initial_prompt
    final_response    = ""

    # ── Step 2: tool dispatch loop ──────────────
    for loop in range(MAX_TOOL_LOOPS):
        response = ask_deepseek(full_conversation)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        # check for tool calls
        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        # run all tool calls
        tool_results = run_tool_calls(tool_calls)

        # feed results back into conversation, minimizing token waste
        full_conversation = (
            f"{full_conversation}\n\n"
            f"[AI_REQ]\n{response}\n"
            f"[SYS_RES]\n{tool_results}\n"
            f"Continue analysis. End with RISK_LEVEL and SUMMARY."
        )

    # ── Step 3: parse structured output ─────────
    vulnerabilities = parse_vulnerabilities(final_response)
    exploits        = parse_exploits(final_response)
    risk_level      = parse_risk_level(final_response)
    summary         = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   final_response,
        "vulnerabilities": vulnerabilities,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan
    }


# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    # Check API key presence
    api_key = os.environ.get("DEEPSEEK_API_KEY")
    if not api_key:
        print("[!] DEEPSEEK_API_KEY not found in .env file.")
        exit(1)
    else:
        print("[+] DeepSeek API key loaded.")

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
