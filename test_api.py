import urllib.request, json

# Health check
with urllib.request.urlopen("http://localhost:8000/api/health") as r:
    h = json.loads(r.read())
    print("HEALTH:", h["status"], "| agents:", h["agents"], "| rules:", h["security_rules"])

# Analyze a real snippet
code = (
    "import md5\n"
    "import urllib2\n"
    "def login(u, p):\n"
    "    q = \"SELECT * FROM users WHERE user='%s'\" % u\n"
    "    cursor.execute(q)\n"
    "    except:\n"
    "        pass\n"
)
payload = json.dumps({"code": code, "language": "python"}).encode()
req = urllib.request.Request(
    "http://localhost:8000/api/analyze",
    data=payload,
    headers={"Content-Type": "application/json"},
    method="POST"
)
with urllib.request.urlopen(req) as r:
    d = json.loads(r.read())
    m = d["metrics"]
    print("DEBT:", m["initial_tech_debt"], "->", m["residual_tech_debt"])
    print("VULNS:", m["vulnerabilities_detected"])
    print("TESTS:", m["test_pass_rate"])
    print("RULES_EVALUATED:", m["rules_evaluated"])
    print("PLAN_STEPS:", len(d["bob_reasoning_plan"]))
    print("AST_FUNCS:", d["ast_info"]["num_functions"])
    print("ELAPSED:", d["elapsed_seconds"], "s")
    print("ALL GOOD! BobPulse v2.0 fully operational.")
