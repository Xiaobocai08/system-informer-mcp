"""Validate ~/.cursor/mcp.json and launch the system-informer entry exactly as a client would."""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mcp_client import McpClient

cfg_path = os.path.join(os.environ["USERPROFILE"], ".cursor", "mcp.json")
with open(cfg_path, "r", encoding="utf-8-sig") as f:   # tolerate a BOM, like Cursor does
    cfg = json.load(f)                       # raises if the JSON is malformed
entry = cfg["mcpServers"]["system-informer"]
print("config entry:", json.dumps(entry, indent=2))

env = dict(os.environ)
env.update(entry.get("env", {}))
c = McpClient(exe=entry["command"], env=env)
init = c.initialize()
tools = c.list_tools()
status = c.call("server_status", {})
c.close()

print("serverInfo :", init["serverInfo"])
print("tools      :", len(tools))
print("elevated   :", status.get("elevated"), "| SI installed:", status.get("systemInformerInstalled"))
assert init["serverInfo"]["name"] == "system-informer" and len(tools) == 54
print("\nCURSOR CONFIG OK")
