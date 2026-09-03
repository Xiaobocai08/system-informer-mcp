import json, sys, time
from mcp_client import McpClient

def p(label, obj, keys=None):
    if keys and isinstance(obj, dict):
        obj = {k: obj[k] for k in keys if k in obj}
    print(f"--- {label}\n{json.dumps(obj, indent=2, ensure_ascii=False)[:1200]}")

def main():
    c = McpClient(); c.initialize()
    try:
        pid = c.call("launch_process", {"command_line": "notepad.exe"})["pid"]
        time.sleep(1.2)

        th = c.call("process_threads", {"pid": pid, "limit": 3})
        p("process_threads", {"threadCount": th.get("threadCount"), "returned": th.get("returned"),
                              "first": (th.get("threads") or [None])[0]})
        assert not th["_isError"], th
        tid = th["threads"][0]["tid"]

        td = c.call("thread_details", {"tid": tid})
        p("thread_details", td, ["processName","tid","pid","state","startAddressSymbolic","tebAddress","priority"])
        assert not td["_isError"], td

        ms = c.call("process_memory_summary", {"pid": pid})
        p("process_memory_summary", ms, ["workingSet_pretty","privateBytes_pretty","virtualSize_pretty","pageFaults"])
        assert not ms["_isError"], ms

        rg = c.call("process_memory_regions", {"pid": pid, "type": "Image", "limit": 3})
        p("process_memory_regions(Image)", {"matchingRegions": rg.get("matchingRegions"),
                                            "committedImage_pretty": rg.get("committedImage_pretty"),
                                            "first": (rg.get("regions") or [None])[0]})
        assert not rg["_isError"], rg
        base = rg["regions"][0]["baseAddress"]

        rd = c.call("read_process_memory", {"pid": pid, "address": base, "size": 64})
        p("read_process_memory@imageBase", {"bytesRead": rd.get("bytesRead"), "firstDumpLine": (rd.get("dump") or [None])[0]})
        assert not rd["_isError"], rd
        assert rd["hex"].lower().startswith("4d5a"), "expected MZ header at image base: " + rd.get("hex","")[:8]

        # search for the MZ signature within the module
        end = hex(int(base,16) + 0x100000)
        sr = c.call("search_process_memory", {"pid": pid, "pattern_hex": "4D 5A 90 00",
                                              "start_address": base, "end_address": end, "max_results": 3})
        p("search_process_memory(MZ)", {"totalMatches": sr.get("totalMatches"), "matches": sr.get("matches")})
        assert not sr["_isError"], sr

        st = c.call("process_memory_strings", {"pid": pid, "min_length": 8, "max_results": 5, "filter": "the"})
        p("process_memory_strings", {"totalFound": st.get("totalFound"), "sample": (st.get("strings") or [])[:3]})
        assert not st["_isError"], st

        c.call("terminate_process", {"pid": pid, "confirm": True})
        print("\nMEM/THREAD OK")
    finally:
        c.close()
        for l in c.stderr_lines: print("[stderr]", l)

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    main()
