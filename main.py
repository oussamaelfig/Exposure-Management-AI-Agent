# main.py
import os
os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"  # ensure Gemini REST API usage
import time
import asyncio
from typing import List, Optional

from dotenv import load_dotenv
import httpx

from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types  # for ADK Content/Part
from google.adk.models.lite_llm import LiteLlm
from google.genai.errors import ClientError
import logging

# small logging setup for local runs
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


# model constants
MODEL_GEMINI = "gemini-2.0-flash"               # current default
MODEL_GPT    = "openai/gpt-4.1"                 # or "openai/gpt-4o-mini"
MODEL_CLAUDE = "anthropic/claude-3-7-sonnet-20250219"  # any supported Claude

# ---------- env / config ----------
load_dotenv()  # loads GOOGLE_API_KEY, TENABLE_* from .env

GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
if not GOOGLE_API_KEY or GOOGLE_API_KEY == "YOUR_GEMINI_API_KEY_HERE":
    raise RuntimeError("Set GOOGLE_API_KEY in .env")

TENABLE_ACCESS_KEY = os.environ.get("TENABLE_ACCESS_KEY")
TENABLE_SECRET_KEY = os.environ.get("TENABLE_SECRET_KEY")
if not (TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY):
    raise RuntimeError("Set TENABLE_ACCESS_KEY and TENABLE_SECRET_KEY in .env")

TENABLE_API = "https://cloud.tenable.com"
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
    "X-ApiKeys": f"accessKey={TENABLE_ACCESS_KEY}; secretKey={TENABLE_SECRET_KEY}",
}

# ---------- tools ----------
from typing import List, Dict, Optional

def compute_since_hours(hours: int) -> dict:
    """
    Convert hours into a Unix timestamp for Tenable filters.
    Returns {'since_unix': int}. Example: hours=24 -> last 24h.
    """
    if hours <= 0:
        return {"status": "error", "error_message": "hours must be > 0"}
    return {"status": "success", "since_unix": int(time.time() - hours * 3600)}

def compute_since_days(days: int) -> dict:
    """
    Convert days into a Unix timestamp for Tenable filters.
    Returns {'since_unix': int}. Example: days=7 -> last 7 days.
    """
    if days <= 0:
        return {"status": "error", "error_message": "days must be > 0"}
    return {"status": "success", "since_unix": int(time.time() - days * 86400)}

def parse_tag_filters(tag_exprs: List[str]) -> dict:
    """
    Convert ['Env:Prod','Location:Austin'] -> {'Env':['Prod'], 'Location':['Austin']}.
    Ignores malformed items (no ':').
    """
    out: Dict[str, List[str]] = {}
    for expr in tag_exprs or []:
        if ":" in expr:
            cat, val = expr.split(":", 1)
            cat, val = cat.strip(), val.strip()
            if cat and val:
                out.setdefault(cat, []).append(val)
    return {"status":"success", "tag_filters": out}

def export_vulns(
    severities: Optional[List[str]],
    tag_filters: Optional[Dict[str, List[str]]],
    since_unix: Optional[int],
    max_count: Optional[int]
) -> dict:
    """
    Export vulnerabilities from Tenable and return up to max_count rows.

    Args:
      severities: e.g. ["critical","high","medium","low"] (default ["critical","high"])
      tag_filters: {'Env':['Prod']} etc. (optional)
      since_unix: unix timestamp for updated_at >= since (optional)
      max_count: cap the number of returned rows (default 200)

    Returns: {status:"success", items:[...]} or {status:"error", error_message:"..."}
    """
    # set defaults inside the function to avoid exposing defaults in generated function schema
    if severities is None:
        severities = ["critical", "high"]
    if max_count is None:
        max_count = 200

    logger.info("--- Tool: export_vulns called. sevs=%s tags=%s since=%s ---", severities, tag_filters, since_unix)

    payload = {"filters": {"severity": severities}}
    if since_unix:
        payload["filters"]["since"] = since_unix
    if tag_filters:
        for cat, values in tag_filters.items():
            if values:
                payload["filters"][f"tag.{cat}"] = values  # correct Tenable syntax

    def _start_export(client, payload):
        r = client.post(f"{TENABLE_API}/vulns/export", headers=HEADERS, json=payload)
        r.raise_for_status()
        return r.json()["export_uuid"]

    def _wait_for_chunks(client, export_uuid, *, poll_interval=2, max_wait_seconds=180):
        """
        Polls Tenable export status until finished or timeout.
        Returns a list of chunk ids (possibly empty).
        Raises RuntimeError on ERROR/CANCELLED or timeout.
        """
        start = time.time()
        last_logged = 0
        while True:
            s = client.get(f"{TENABLE_API}/vulns/export/{export_uuid}/status", headers=HEADERS)
            s.raise_for_status()
            sj = s.json()

            status = sj.get("status")
            chunks = sj.get("chunks_available") or []  # normalize to list
            now = time.time()

            # periodic log (every ~10s)
            if now - last_logged > 10:
                print(f"[export status] uuid={export_uuid} status={status} chunks={chunks}")
                last_logged = now

            if status == "FINISHED":
                # exit even if there are zero chunks
                return chunks

            if status in ("ERROR", "CANCELLED"):
                raise RuntimeError(f"Export {status.lower()} for {export_uuid}: {sj}")

            if now - start > max_wait_seconds:
                raise TimeoutError(f"Timed out waiting for export {export_uuid}: last={sj}")

            time.sleep(poll_interval)


    def _download_chunks(client, export_uuid, chunks, max_count):
        results = []
        for ch in chunks:
            chunk = client.get(f"{TENABLE_API}/vulns/export/{export_uuid}/chunks/{ch}", headers=HEADERS)
            chunk.raise_for_status()
            for row in chunk.json():
                results.append(row)
                if len(results) >= max_count:
                    return results
        return results

    # attempt to run export; if Tenable rejects the tag filter property, retry without it and filter locally
    try:
        with httpx.Client(timeout=30) as c:
            try:
                export_uuid = _start_export(c, payload)
            except httpx.HTTPStatusError as e:
                # detect unknown property related to tags and retry without tag filters
                text = (e.response.text or "").lower()
                if e.response.status_code in (400, 422) and ("unknown property" in text or "asset.tags" in text or "tag." in text):
                    logger.warning("Tenable rejected filter payload; retrying without tag filters and will apply local filtering instead: %s", e.response.text[:200])
                    # remove tag.* filters and proceed
                    payload_no_tags = {"filters": {k: v for k, v in payload["filters"].items() if not str(k).startswith("tag.")}}
                    export_uuid = _start_export(c, payload_no_tags)
                    chunks = _wait_for_chunks(c, export_uuid)
                    results = _download_chunks(c, export_uuid, chunks, max_count)
                    # apply local filtering by inspecting common tag fields in returned rows
                    if tag_filters:
                        filtered = []
                        for row in results:
                            # try several common locations for tags
                            candidate_tags = []
                            try:
                                # Tenable sometimes nests tags under asset.tags or asset -> tags
                                candidate_tags.extend([t for t in (row.get("asset", {}) or {}).get("tags", [])])
                            except Exception:
                                pass
                            for key in ("tags", "asset_tags", "asset.tags", "asset_tags.value"):
                                v = row.get(key)
                                if isinstance(v, list):
                                    candidate_tags.extend(v)
                                elif isinstance(v, str):
                                    candidate_tags.append(v)

                            # normalize candidate tags to strings and match any requested tag value
                            candidate_norm = set(str(x).lower() for x in candidate_tags if x is not None)
                            matched = False
                            for cat, vals in tag_filters.items():
                                for val in vals:
                                    if val.lower() in candidate_norm or f"{cat.lower()}:{val.lower()}" in candidate_norm:
                                        matched = True
                                        break
                                if matched:
                                    break
                            if matched:
                                filtered.append(row)
                            if len(filtered) >= max_count:
                                break
                        return {"status": "success", "items": filtered}
                    return {"status": "success", "items": results}
                # otherwise re-raise to be handled below
                raise

            # normal path when initial payload accepted
            chunks = _wait_for_chunks(c, export_uuid)
            results = _download_chunks(c, export_uuid, chunks, max_count)
            return {"status": "success", "items": results}

    except httpx.HTTPStatusError as e:
        return {"status": "error", "error_message": f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"status": "error", "error_message": f"{type(e).__name__}: {e}"}

# ---------- Step 3 tools: assets + (optional) lumin ----------
from typing import Dict, Any

def export_assets(max_count: int = 200) -> dict:
    """
    Export assets via /assets/v2/export and return up to max_count rows.
    (Simple baseline: no filters in Step 3. We'll add filters later if needed.)
    """
    print(f"--- Tool: export_assets called. max_count={max_count} ---")

    def _start_export(client):
        # add a reasonable chunk_size (e.g., 1000). Adjust if your org is large.
        payload = {
            "chunk_size": 1000,
            # add filters later if you want (e.g., by tag, last_seen, etc.)
            # "filters": { ... }
        }
        r = client.post(f"{TENABLE_API}/assets/v2/export", headers=HEADERS, json=payload)
        r.raise_for_status()
        return r.json()["export_uuid"]

    def _wait_for_chunks(client, export_uuid, *, poll_interval=2, max_wait_seconds=180):
        start = time.time()
        last_logged = 0
        while True:
            s = client.get(f"{TENABLE_API}/assets/v2/export/{export_uuid}/status", headers=HEADERS)
            s.raise_for_status()
            sj = s.json()
            status = sj.get("status")
            chunks = sj.get("chunks_available") or []
            now = time.time()
            if now - last_logged > 10:
                print(f"[assets status] uuid={export_uuid} status={status} chunks={chunks}")
                last_logged = now
            if status == "FINISHED":
                return chunks
            if status in ("ERROR", "CANCELLED"):
                raise RuntimeError(f"Assets export {status.lower()} for {export_uuid}: {sj}")
            if now - start > max_wait_seconds:
                raise TimeoutError(f"Timed out waiting for assets export {export_uuid}: last={sj}")
            time.sleep(poll_interval)

    def _download_chunks(client, export_uuid, chunks, max_count):
        results = []
        for ch in chunks:
            chunk = client.get(f"{TENABLE_API}/assets/v2/export/{export_uuid}/chunks/{ch}", headers=HEADERS)
            chunk.raise_for_status()
            for row in chunk.json():
                results.append(row)
                if len(results) >= max_count:
                    return results
        return results

    try:
        with httpx.Client(timeout=30) as c:
            uuid = _start_export(c)
            chunks = _wait_for_chunks(c, uuid)
            items = _download_chunks(c, uuid, chunks, max_count)
            return {"status": "success", "items": items}
    except httpx.HTTPStatusError as e:
        return {"status":"error","error_message":f"HTTP {e.response.status_code}: {e.response.text}"}
    except Exception as e:
        return {"status":"error","error_message":f"{type(e).__name__}: {e}"}

def lumin_ces_metrics() -> dict:
    """
    Try to fetch org-level exposure metrics (if available in your tenant).
    Gracefully returns an error if not enabled.
    """
    print(f"--- Tool: lumin_ces_metrics called ---")
    try:
        r = httpx.get(f"{TENABLE_API}/lumin/metrics", headers=HEADERS, timeout=30)
        if r.status_code == 200:
            return {"status":"success", "metrics": r.json()}
        return {"status":"error", "error_message": f"Endpoint returned {r.status_code}: {r.text[:200]}..."}
    except Exception as e:
        return {"status":"error", "error_message": f"{type(e).__name__}: {e}"}


# ---------- single agent ----------
# Using Gemini by name; ADK reads GOOGLE_API_KEY automatically (since we set GOOGLE_GENAI_USE_VERTEXAI=False)
AGENT_MODEL = "gemini-2.0-flash"

vuln_agent = Agent(
    name="vuln_agent_step1",
    model=AGENT_MODEL,
    description="Fetches vulnerabilities from Tenable and summarizes top items.",
    instruction=(
        "You can use tools to gather Tenable data:\n"
        "- If the user mentions a time window like 'last 24h', call 'compute_since_hours' with hours.\n"
        "- If the user mentions 'last 7d', call 'compute_since_days' with days.\n"
        "- If the user provides tags like 'Env:Prod' or 'Location:Austin', call 'parse_tag_filters' "
        "  to build a dict like {'Env':['Prod']}.\n"
        "- Then call 'export_vulns' with explicit arguments (severities, tag_filters, since_unix, max_count). "
        "  It's OK to omit tag_filters/since_unix if not provided.\n\n"
        "After the tool returns, always produce a clear textual summary: counts by severity and a few top "
        "findings with plugin_id, plugin_name, severity, and an asset identifier if present. "
        "If the tool returns an error, explain it briefly."
    ),
    tools=[compute_since_hours, compute_since_days, parse_tag_filters, export_vulns],
)

# ---------- Step 3 agents: inventory + risk ----------
inventory_agent = Agent(
    name="inventory_agent",
    model=AGENT_MODEL,  # reuse your current default model
    description="Handles asset inventory/export and produces a concise summary.",
    instruction=(
        "Call 'export_assets' (cap results using max_count). "
        "Then summarize: show the total assets returned and list a handful with key fields "
        "(e.g., hostname, ipv4, operating_system, last_seen if present). "
        "Always produce a clear textual summary. If the tool errors, report it briefly."
    ),
    tools=[export_assets],
)

risk_agent = Agent(
    name="risk_agent",
    model=AGENT_MODEL,
    description="Answers exposure/risk questions (org-level).",
    instruction=(
        "Call 'lumin_ces_metrics' to get exposure metrics (if available). "
        "If metrics are available, explain CES/grades succinctly. "
        "If not available, say that org-wide exposure metrics aren't enabled and suggest "
        "using vulnerability trends or asset criticality in later steps."
    ),
    tools=[lumin_ces_metrics],
)

# ---------- Step 3 root/orchestrator ----------
exposure_root = Agent(
    name="exposure_root",
    model=AGENT_MODEL,
    description="Root orchestrator for Exposure Management.",
    instruction=(
        "You coordinate the team:\n"
        "- If the user asks for vulnerabilities or findings, handle it yourself by calling 'export_vulns'. "
        "  Use 'compute_since_hours' or 'compute_since_days' if a time window is mentioned, and "
        "  'parse_tag_filters' for tag inputs like 'Env:Prod'. Call 'export_vulns' at most once per request, "
        "  then produce a clear summary (counts by severity + top items).\n"
        "- If the user asks about assets/inventory/hosts, delegate to 'inventory_agent'.\n"
        "- If the user asks about exposure/risk/score or Lumin, delegate to 'risk_agent'.\n"
        "If a query mixes multiple intents, start with the most specific need and clearly state what you handled."
        "Call each tool at most once per user request; after the tool returns, produce a textual summary."
    ),
    tools=[compute_since_hours, compute_since_days, parse_tag_filters, export_vulns],  # root keeps vuln tools
    sub_agents=[inventory_agent, risk_agent],  # enable delegation
)


# ---------- helper to make copies for other models ----------
def make_vuln_agent_for_model(name: str, model_obj) -> Agent:
    """
    Create a copy of the vuln agent for a different model (Gemini/GPT/Claude).
    Reuses the same tools and instructions.
    """
    return Agent(
        name=name,
        model=model_obj,
        description="Fetches vulnerabilities from Tenable and summarizes top items.",
        instruction=(
            "You can use tools to gather Tenable data:\n"
            "- If the user mentions a time window like 'last 24h', call 'compute_since_hours' with hours.\n"
            "- If the user mentions 'last 7d', call 'compute_since_days' with days.\n"
            "- If the user provides tags like 'Env:Prod' or 'Location:Austin', call 'parse_tag_filters' "
            "  to build a dict like {'Env':['Prod']}.\n"
            "- Then call 'export_vulns' with explicit arguments (severities, tag_filters, since_unix, max_count). "
            "  It's OK to omit tag_filters/since_unix if not provided.\n\n"
            "Call 'export_vulns' at most once per user request. After the tool returns, always produce a clear textual "
            "summary: counts by severity and a few top findings with plugin_id, plugin_name, severity, and an asset "
            "identifier if present. If the tool returns an error, explain it briefly."
        ),
        tools=[compute_since_hours, compute_since_days, parse_tag_filters, export_vulns],
    )

# ---------- runner + a tiny helper to call it ----------
async def ask_agent(query: str, runner: Runner, user_id: str, session_id: str):
    print(f"\n>>> User: {query}")
    content = types.Content(role="user", parts=[types.Part(text=query)])

    async def _once():
        final_text = None
        async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
            if event.is_final_response():
                if event.content and event.content.parts:
                    texts = []
                    non_text_parts = []
                    for p in event.content.parts:
                        if getattr(p, "text", None):
                            texts.append(p.text)
                        else:
                            # try to extract function_call-like info if present for debugability
                            fc = getattr(p, "function_call", None)
                            name = getattr(p, "name", None)
                            args = getattr(p, "arguments", None)
                            if fc:
                                non_text_parts.append(f"function_call={fc}")
                            elif name or args:
                                non_text_parts.append(f"name={name} args={args}")
                            else:
                                non_text_parts.append(repr(p))

                    final_text = "\n".join(t for t in texts if t)
                    if non_text_parts:
                        final_text = (final_text + "\n\n[Non-text parts present: " + ", ".join(non_text_parts) + "]") if final_text else ("[Non-text parts: " + ", ".join(non_text_parts) + "]")
                final_text = final_text or "(No text in final response)"
                break
        return final_text

    try:
        out = await _once()
    except ClientError as e:
        # Retry ONCE on 429 throttle
        if getattr(e, "status_code", None) == 429:
            print("Hit 429 (RESOURCE_EXHAUSTED). Backing off briefly and retrying once...")
            await asyncio.sleep(3)
            out = await _once()
        else:
            raise

    print(f"<<< Agent:\n{out}\n")

async def main():
    svc = InMemorySessionService()
    app = "tenable_exposure_app_step1"
    user = "user_1"
    sess = "session_001"
    # ---- Multi-model (optional) ----
    # We create separate sessions so the histories don't mix
    query1 = "Show me critical & high vulns (cap at ~100)."
    query2 = "List high vulns for assets tagged Env:Prod updated in last 24h."

    # GPT (if OPENAI_API_KEY is present)
    if os.environ.get("OPENAI_API_KEY"):
        try:
            agent_gpt = make_vuln_agent_for_model("vuln_agent_gpt", LiteLlm(model=MODEL_GPT))
            svc_gpt = InMemorySessionService()
            await svc_gpt.create_session(app_name="tenable_app_gpt", user_id="u_gpt", session_id="s_gpt")
            runner_gpt = Runner(agent=agent_gpt, app_name="tenable_app_gpt", session_service=svc_gpt)

            print("\n=== Testing GPT agent ===")
            await ask_agent(query1, runner_gpt, "u_gpt", "s_gpt")
            await ask_agent(query2, runner_gpt, "u_gpt", "s_gpt")
        except Exception as e:
            print(f"[GPT] Skipping due to error: {e}")

    # Claude (if ANTHROPIC_API_KEY is present)
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            agent_claude = make_vuln_agent_for_model("vuln_agent_claude", LiteLlm(model=MODEL_CLAUDE))
            svc_claude = InMemorySessionService()
            await svc_claude.create_session(app_name="tenable_app_claude", user_id="u_claude", session_id="s_claude")
            runner_claude = Runner(agent=agent_claude, app_name="tenable_app_claude", session_service=svc_claude)

            print("\n=== Testing Claude agent ===")
            await ask_agent(query1, runner_claude, "u_claude", "s_claude")
            await ask_agent(query2, runner_claude, "u_claude", "s_claude")
        except Exception as e:
            print(f"[Claude] Skipping due to error: {e}")

    # create the session
    await svc.create_session(app_name=app, user_id=user, session_id=sess)

    runner = Runner(agent=vuln_agent, app_name=app, session_service=svc)

    # Try a couple of prompts
    await ask_agent("Show me critical & high vulns (cap at ~100).", runner, user, sess)
    # You can pass filter hints; the agent will translate to the tool call.
    await ask_agent("List high vulns for assets tagged Env:Prod updated in last 24h.", runner, user, sess)

    # ---- Step 3: Team test (root + delegation) ----
    svc_team = InMemorySessionService()
    await svc_team.create_session(app_name="tenable_team_app", user_id="u_team", session_id="s_team")
    runner_team = Runner(agent=exposure_root, app_name="tenable_team_app", session_service=svc_team)

    print("\n=== Team test (root + delegation) ===")
    # Inventory path -> should DELEGATE to inventory_agent
    await ask_agent("List assets (cap 50).", runner_team, "u_team", "s_team")

    # Vulnerability path -> root handles with export_vulns
    await ask_agent("Show critical vulns from the last 24h (cap 100).", runner_team, "u_team", "s_team")

    # Risk path -> should DELEGATE to risk_agent
    await ask_agent("What is our exposure score in Lumin?", runner_team, "u_team", "s_team")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
# End of main.py