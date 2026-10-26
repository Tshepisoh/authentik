"""Runs only the Authentik sandbox worker on a Hugging Face Space (Gradio SDK, no Gradio UI).

The Gradio SDK only gives us Python, so this installs Node.js and Playwright's Chromium on
first start, works out which Chromium sandbox the Space allows, then runs the worker on the
Space's port (7860). The worker gets a clean environment holding only its shared secret.
See deploy/hf-sandbox/README.md in the Authentik repository.
"""
import os
import pathlib
import subprocess
import sys
import tarfile
import urllib.request

APP = pathlib.Path(__file__).resolve().parent
HOME = pathlib.Path.home()
NODE_VERSION = "v24.21.0"
NODE_BIN = HOME / f"node-{NODE_VERSION}-linux-x64" / "bin"
SECRET = os.environ.get("SANDBOX_WORKER_SECRET", "")

if len(SECRET) < 32:
    sys.exit("Add the SANDBOX_WORKER_SECRET secret (32+ characters) in the Space settings.")

env = {"PATH": f"{NODE_BIN}:/usr/bin:/bin", "HOME": str(HOME)}


def run(*cmd: str) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=APP, env=env, check=True)


if not (NODE_BIN / "node").exists():
    url = f"https://nodejs.org/dist/{NODE_VERSION}/node-{NODE_VERSION}-linux-x64.tar.gz"
    print("Downloading", url, flush=True)
    with urllib.request.urlopen(url) as r, tarfile.open(fileobj=r, mode="r|gz") as t:
        try:
            t.extractall(HOME, filter="data")
        except TypeError:  # Python without extraction filters
            t.extractall(HOME)

if not (APP / "node_modules").exists():
    run("npm", "ci", "--omit=dev", "--ignore-scripts", "--include-workspace-root",
        "--workspace", "@authentik/shared", "--workspace", "@authentik/sandbox-worker")

try:
    run("node", "node_modules/playwright-core/cli.js", "install", "--only-shell", "chromium")
except subprocess.CalledProcessError:
    run("node", "node_modules/playwright-core/cli.js", "install", "chromium")

PROBE = (
    "const o=JSON.parse(process.argv[1]);require('playwright-core').chromium.launch(o)"
    ".then(b=>b.close()).then(()=>process.exit(0),e=>{console.error(String(e.message).split('\\n')[0]);process.exit(1)})"
)


def launches(options: dict) -> bool:
    import json
    return subprocess.run(["node", "-e", PROBE, json.dumps(options)], cwd=APP, env=env, timeout=60).returncode == 0


# Prefer Chromium's own sandbox; the Space may not allow the user namespaces it needs.
choice = None
for executable in (None, "/usr/bin/chromium"):
    for sandbox in (True, False):
        options = {"chromiumSandbox": sandbox, **({"executablePath": executable} if executable else {})}
        if launches(options):
            choice = (executable, sandbox)
            break
    if choice:
        break
if not choice:
    sys.exit("Chromium could not start in this Space.")

executable, sandbox = choice
if not sandbox:
    print("WARNING: Chromium's own sandbox is OFF here. Risky sites are contained by the worker's "
          "egress proxy and throwaway profiles only, and this Space holds no other secrets.", flush=True)

worker_env = {
    **env,
    # The worker refuses CHROMIUM_SANDBOX=false in production; only those checks differ.
    "NODE_ENV": "production" if sandbox else "development",
    "HOST": "0.0.0.0",
    "PORT": "7860",
    "WORKER_SECRET": SECRET,
    "MAX_SESSIONS": os.environ.get("MAX_SESSIONS", "3"),
    "MAX_SESSION_SECONDS": "900",
    "CHROMIUM_SANDBOX": "true" if sandbox else "false",
}
if executable:
    worker_env["CHROMIUM_EXECUTABLE_PATH"] = executable

print("Starting the sandbox worker", flush=True)
sys.exit(subprocess.run(["node", "sandbox-worker/dist/index.js"], cwd=APP, env=worker_env).returncode)
