import json, sys, time, os, tempfile
from mcp_client import McpClient

def main():
    c = McpClient(); c.initialize()
    # create a unique file and open it in notepad so a File handle exists
    d = tempfile.gettempdir()
    fname = os.path.join(d, "si_mcp_lock_test_marker.txt")
    with open(fname, "w") as f:
        f.write("hello")
    try:
        pid = c.call("launch_process", {"command_line": f'notepad.exe "{fname}"'})["pid"]
        time.sleep(1.5)

        lh = c.call("list_handles", {"pid": pid, "type": "File", "limit": 8})
        print("list_handles File count:", lh.get("totalHandles"), "returned:", lh.get("returned"))
        names = [h.get("name") for h in lh.get("handles", []) if h.get("name")]
        print("some file handle names:", json.dumps(names[:5], ensure_ascii=False))

        fb = c.call("find_handles_by_name", {"name": "si_mcp_lock_test_marker", "type": "File", "limit": 5})
        print("find_handles_by_name:", json.dumps(fb, indent=2, ensure_ascii=False)[:900])
        ok = fb.get("matches", 0) >= 1
        c.call("terminate_process", {"pid": pid, "confirm": True})
        print("\nHANDLES", "OK" if ok else "PARTIAL (notepad may not keep the file handle open)")
    finally:
        c.close()
        try: os.remove(fname)
        except: pass
        for l in c.stderr_lines: print("[stderr]", l)

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
