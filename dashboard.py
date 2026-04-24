# dashboard.py
import json
import socket
import time
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ── Config ────────────────────────────────────────────────────────────────────
VALIDATORS = [
    {"name": "Validator A", "host": "127.0.0.1", "port": 5504},
    {"name": "Validator B", "host": "127.0.0.1", "port": 5503},
    {"name": "Validator C", "host": "127.0.0.1", "port": 5502},
    # Add more validators here as your group spins them up:
    # {"name": "Validator B", "host": "10.101.169.147", "port": 5001},
]
# ─────────────────────────────────────────────────────────────────────────────


def query_validator(host: str, port: int, message: dict, timeout: float = 3.0) -> dict:
    """Send a TCP query to a validator and return the JSON response."""
    try:
        payload = (json.dumps(message) + "\n").encode("utf-8")
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.sendall(payload)
            sock.settimeout(timeout)
            raw = b""
            while not raw.endswith(b"\n"):
                chunk = sock.recv(4096)
                if not chunk:
                    break
                raw += chunk
        return json.loads(raw.strip())
    except (ConnectionRefusedError, TimeoutError, OSError):
        return None   # validator offline


@app.route("/api/status")
def api_status():
    results = []
    for v in VALIDATORS:
        resp = query_validator(v["host"], v["port"], {"type": "get_status"})
        if resp and resp.get("status") == "ok":
            results.append({
                "name":             v["name"],
                "host":             v["host"],
                "port":             v["port"],
                "online":           True,
                "chain_height":     resp["chain_height"],
                "pending_count":    resp["pending_count"],
                "last_block_time":  resp["last_block_time"],
                "last_block_hash":  resp["last_block_hash"],
            })
        else:
            results.append({
                "name":   v["name"],
                "host":   v["host"],
                "port":   v["port"],
                "online": False,
            })
    return jsonify(results)


@app.route("/api/balances")
def api_balances():
    # Merge balances across all online validators (take the max per key)
    merged = {}
    for v in VALIDATORS:
        resp = query_validator(v["host"], v["port"], {"type": "get_balances"})
        if resp and resp.get("status") == "ok":
            for pub_key, balance in resp["balances"].items():
                merged[pub_key] = max(merged.get(pub_key, 0), balance)

    # Sort by balance descending, format for display
    sorted_balances = sorted(merged.items(), key=lambda x: x[1], reverse=True)
    return jsonify([
        {"public_key": k, "short_key": k[:8] + "...", "balance": round(v, 4)}
        for k, v in sorted_balances
    ])


@app.route("/api/blocks")
def api_blocks():
    # Pull recent blocks from the first online validator
    for v in VALIDATORS:
        resp = query_validator(v["host"], v["port"], {"type": "get_blocks", "count": 20})
        if resp and resp.get("status") == "ok":
            blocks = []
            for b in resp["blocks"]:
                blocks.append({
                    "index":         b["index"],
                    "hash":          b["hash"],
                    "short_hash":    b["hash"][:12] + "...",
                    "timestamp":     b["timestamp"],
                    "record_count":  len(b.get("records", [])),
                    "records":       b.get("records", []),
                })
            return jsonify(blocks)
    return jsonify([])


@app.route("/")
def index():
    return DASHBOARD_HTML


# ── Embedded HTML dashboard ───────────────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>DePIN Dashboard</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; }
    header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px;
             display: flex; align-items: center; gap: 12px; }
    header h1 { font-size: 18px; color: #58a6ff; }
    .badge { font-size: 11px; background: #21262d; border: 1px solid #30363d;
             padding: 2px 8px; border-radius: 10px; color: #8b949e; }
    #refresh-time { margin-left: auto; font-size: 12px; color: #8b949e; }
    main { padding: 24px; display: grid; gap: 24px; }

    section h2 { font-size: 14px; color: #8b949e; text-transform: uppercase;
                 letter-spacing: 1px; margin-bottom: 12px; }

    /* Validator cards */
    #validators { display: grid; grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); gap: 12px; }
    .v-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .v-card.online  { border-left: 3px solid #3fb950; }
    .v-card.offline { border-left: 3px solid #f85149; opacity: 0.6; }
    .v-name  { font-weight: bold; color: #e6edf3; margin-bottom: 8px; }
    .v-stat  { font-size: 12px; color: #8b949e; margin-top: 4px; }
    .v-stat span { color: #c9d1d9; }
    .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
    .dot.green { background: #3fb950; }
    .dot.red   { background: #f85149; }

    /* Balances table */
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 12px; color: #8b949e; border-bottom: 1px solid #30363d;
         font-weight: normal; font-size: 11px; text-transform: uppercase; }
    td { padding: 8px 12px; border-bottom: 1px solid #21262d; }
    tr:hover td { background: #161b22; }
    .mono { font-family: monospace; font-size: 12px; color: #79c0ff; }
    .balance-val { color: #3fb950; font-weight: bold; }

    /* Blocks */
    #blocks-list { display: grid; gap: 8px; }
    .block-card { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
                  padding: 12px 16px; display: grid;
                  grid-template-columns: 60px 1fr 1fr 80px; align-items: center; gap: 12px; }
    .block-index { color: #58a6ff; font-weight: bold; }
    .block-hash  { font-size: 12px; color: #8b949e; }
    .block-time  { font-size: 12px; color: #8b949e; }
    .block-recs  { text-align: right; font-size: 12px;
                   background: #21262d; padding: 2px 8px; border-radius: 10px; }

    .empty { color: #8b949e; font-size: 13px; padding: 12px 0; }
  </style>
</head>
<body>
  <header>
    <h1>⛓ DePIN Dashboard</h1>
    <span class="badge">Proof-of-Uptime</span>
    <span id="refresh-time">Updating...</span>
  </header>
  <main>
    <section>
      <h2>Validator Health</h2>
      <div id="validators"><p class="empty">Loading...</p></div>
    </section>
    <section>
      <h2>Balances</h2>
      <table>
        <thead><tr><th>Public Key</th><th>Balance (tokens)</th></tr></thead>
        <tbody id="balances-body"><tr><td colspan="2" class="empty">Loading...</td></tr></tbody>
      </table>
    </section>
    <section>
      <h2>Recent Blocks</h2>
      <div id="blocks-list"><p class="empty">Loading...</p></div>
    </section>
  </main>

  <script>
    function timeAgo(ts) {
      if (!ts) return 'never';
      const diff = Math.floor(Date.now() / 1000 - ts);
      if (diff < 5)   return 'just now';
      if (diff < 60)  return diff + 's ago';
      if (diff < 3600) return Math.floor(diff/60) + 'm ago';
      return Math.floor(diff/3600) + 'h ago';
    }

    async function fetchJSON(url) {
      const r = await fetch(url);
      return r.json();
    }

    async function refresh() {
      // Validators
      const validators = await fetchJSON('/api/status').catch(() => []);
      const vDiv = document.getElementById('validators');
      if (!validators.length) {
        vDiv.innerHTML = '<p class="empty">No validators configured.</p>';
      } else {
        vDiv.innerHTML = validators.map(v => v.online ? `
          <div class="v-card online">
            <div class="v-name"><span class="dot green"></span>${v.name}</div>
            <div class="v-stat">Host: <span>${v.host}:${v.port}</span></div>
            <div class="v-stat">Chain height: <span>${v.chain_height}</span></div>
            <div class="v-stat">Pending records: <span>${v.pending_count}</span></div>
            <div class="v-stat">Last block: <span>${timeAgo(v.last_block_time)}</span></div>
            <div class="v-stat">Last hash: <span>${v.last_block_hash?.slice(0,12)}...</span></div>
          </div>` : `
          <div class="v-card offline">
            <div class="v-name"><span class="dot red"></span>${v.name}</div>
            <div class="v-stat">Host: <span>${v.host}:${v.port}</span></div>
            <div class="v-stat" style="color:#f85149">Offline</div>
          </div>`
        ).join('');
      }

      // Balances
      const balances = await fetchJSON('/api/balances').catch(() => []);
      const tbody = document.getElementById('balances-body');
      tbody.innerHTML = balances.length
        ? balances.map(b => `
            <tr>
              <td class="mono">${b.public_key}</td>
              <td class="balance-val">${b.balance}</td>
            </tr>`).join('')
        : '<tr><td colspan="2" class="empty">No balances yet.</td></tr>';

      // Blocks
      const blocks = await fetchJSON('/api/blocks').catch(() => []);
      const bDiv = document.getElementById('blocks-list');
      bDiv.innerHTML = blocks.length
        ? blocks.map(b => `
            <div class="block-card">
              <div class="block-index">#${b.index}</div>
              <div class="block-hash">${b.short_hash}</div>
              <div class="block-time">${timeAgo(b.timestamp)}</div>
              <div class="block-recs">${b.record_count} record${b.record_count !== 1 ? 's' : ''}</div>
            </div>`).join('')
        : '<p class="empty">No blocks yet.</p>';

      document.getElementById('refresh-time').textContent =
        'Last updated: ' + new Date().toLocaleTimeString();
    }

    refresh();
    setInterval(refresh, 5000);  // poll every 5 seconds
  </script>
</body>
</html>
"""

if __name__ == "__main__":
    print("Dashboard running at http://localhost:8080")
    app.run(host="0.0.0.0", port=8080, debug=False)