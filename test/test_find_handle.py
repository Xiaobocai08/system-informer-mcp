import sys, time
from mcp_client import McpClient

def main():
    c = McpClient(); c.initialize()
    # open a well-known file in notepad; then search for a path substring that must match
    pid = c.call("launch_process", {"command_line": r"notepad.exe C:\Windows\System32\drivers\etc\hosts"})["pid"]
    time.sleep(1.5)
    t0 = time.time()
    fb = c.call("find_handles_by_name", {"name": "drivers\\etc", "type": "File", "limit": 5})
    dt = time.time() - t0
    print("elapsedSec=%.1f matches=%d scanned=%d" % (dt, fb.get("matches"), fb.get("namedHandlesScanned")))
    for r in fb.get("results", [])[:5]:
        print("  pid", r.get("pid"), r.get("processImage"), "->", r.get("name"))
    c.call("terminate_process", {"pid": pid, "confirm": True})
    c.close()
    for l in c.stderr_lines: print("[stderr]", l)

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
