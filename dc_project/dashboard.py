from __future__ import annotations

from collections import defaultdict
from flask import Flask, jsonify, render_template_string

from dc_project.store import JsonStateStore


app = Flask(__name__)
store = JsonStateStore()


TOPOLOGY = {
    "nodes": [
        {"id": "h1", "label": "h1\nAGV"},
        {"id": "h2", "label": "h2\nPLC"},
        {"id": "h3", "label": "h3\nFarm"},
        {"id": "h4", "label": "h4\nBaggage"},
        {"id": "h5", "label": "h5\nEdge"},
        {"id": "s1", "label": "s1\nSwitch"},
    ],
    "links": [
        {"source": "h1", "target": "s1"},
        {"source": "h2", "target": "s1"},
        {"source": "h3", "target": "s1"},
        {"source": "h4", "target": "s1"},
        {"source": "h5", "target": "s1"},
    ],
}


HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Slicing Dashboard</title>
  <style>
    :root {
      --bg: #f3efe5;
      --panel: rgba(255,255,255,0.85);
      --ink: #152033;
      --pass: #2e8b57;
      --steer: #1f67d2;
      --drop: #c2362b;
      --wire: #aab4c6;
      --accent: #f2a65a;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(242,166,90,0.35), transparent 30%),
        linear-gradient(135deg, #f3efe5 0%, #dbe7f4 100%);
      min-height: 100vh;
    }
    .wrap {
      max-width: 1380px;
      margin: 0 auto;
      padding: 24px;
      display: grid;
      grid-template-columns: 1.3fr 1fr;
      gap: 20px;
    }
    .panel {
      background: var(--panel);
      backdrop-filter: blur(14px);
      border: 1px solid rgba(21,32,51,0.08);
      border-radius: 22px;
      box-shadow: 0 18px 60px rgba(21,32,51,0.12);
      padding: 20px;
    }
    h1, h2 { margin: 0 0 12px 0; }
    h1 { font-size: 30px; }
    h2 { font-size: 18px; }
    .hero { grid-column: 1 / -1; display: flex; justify-content: space-between; align-items: end; gap: 16px; }
    .hero p { max-width: 860px; margin: 0; line-height: 1.5; }
    .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; }
    .stat {
      border-radius: 18px;
      padding: 16px;
      background: rgba(255,255,255,0.8);
      border: 1px solid rgba(21,32,51,0.06);
    }
    .stat b { display: block; font-size: 26px; margin-top: 6px; }
    .layout { display: contents; }
    svg { width: 100%; height: 520px; }
    .legend { display: flex; gap: 16px; margin-top: 12px; flex-wrap: wrap; }
    .legend span::before {
      content: "";
      display: inline-block;
      width: 12px;
      height: 12px;
      border-radius: 999px;
      margin-right: 8px;
      vertical-align: middle;
    }
    .legend .pass::before { background: var(--pass); }
    .legend .steer::before { background: var(--steer); }
    .legend .drop::before { background: var(--drop); }
    .legend .idle::before { background: var(--wire); }
    table { width: 100%; border-collapse: collapse; font-size: 14px; }
    th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid rgba(21,32,51,0.08); }
    .pill {
      display: inline-block;
      border-radius: 999px;
      padding: 4px 10px;
      font-weight: 700;
      color: white;
    }
    .PASS { background: var(--pass); }
    .STEER { background: var(--steer); }
    .DROP { background: var(--drop); }
    .grid-two { display: grid; grid-template-columns: 1fr; gap: 20px; }
    .muted { color: rgba(21,32,51,0.72); }
    .event-list { max-height: 290px; overflow: auto; }
    .event {
      display: grid;
      grid-template-columns: 72px 1.2fr 1fr 80px 55px;
      gap: 10px;
      padding: 10px 0;
      border-bottom: 1px solid rgba(21,32,51,0.08);
      font-size: 14px;
    }
    .badge {
      width: 14px;
      height: 14px;
      border-radius: 999px;
      display: inline-block;
      margin-right: 8px;
    }
    @media (max-width: 1080px) {
      .wrap { grid-template-columns: 1fr; }
      .stats { grid-template-columns: repeat(2, 1fr); }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero panel">
      <div>
        <h1>Network Slicing Live Dashboard</h1>
        <p class="muted">This view shows the software slicing pipeline in action: active slice rules, live packet counts, recent flow decisions, queue assignment, and a topology view where links light up green for <b>PASS</b>, blue for <b>STEER</b>, and red for <b>DROP</b>.</p>
      </div>
      <div class="muted">Refresh: <span id="updatedAt">waiting...</span></div>
    </div>

    <div class="panel" style="grid-column: 1 / -1;">
      <div class="stats" id="stats"></div>
    </div>

    <div class="panel">
      <h2>Colored Topology</h2>
      <svg viewBox="0 0 760 520">
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="4" result="blur"/>
            <feMerge>
              <feMergeNode in="blur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        <g id="links"></g>
        <g id="nodes"></g>
      </svg>
      <div class="legend">
        <span class="pass">PASS</span>
        <span class="steer">STEER</span>
        <span class="drop">DROP</span>
        <span class="idle">Idle</span>
      </div>
    </div>

    <div class="grid-two">
      <div class="panel">
        <h2>Active Slice Rules</h2>
        <table>
          <thead>
            <tr><th>Service</th><th>Action</th><th>Queue</th><th>Priority</th><th>Max BW</th></tr>
          </thead>
          <tbody id="rulesTable"></tbody>
        </table>
      </div>

      <div class="panel">
        <h2>Recent Flow Events</h2>
        <div class="event-list" id="events"></div>
      </div>
    </div>

    <div class="panel" style="grid-column: 1 / -1;">
      <h2>Per-Slice Metrics</h2>
      <table>
        <thead>
          <tr><th>Service</th><th>Action</th><th>Packets</th><th>Bytes</th><th>Drop Rate</th><th>Queue Hits</th></tr>
        </thead>
        <tbody id="metricsTable"></tbody>
      </table>
    </div>
  </div>

  <script>
    const topologyPositions = {
      h1: {x: 120, y: 100}, h2: {x: 120, y: 210}, h3: {x: 120, y: 320},
      h4: {x: 120, y: 430}, s1: {x: 390, y: 260}, h5: {x: 640, y: 260}
    };
    const colors = { PASS: "#2e8b57", STEER: "#1f67d2", DROP: "#c2362b", IDLE: "#aab4c6" };
    const labels = {
      h1: ["h1", "AGV"], h2: ["h2", "PLC"], h3: ["h3", "Farm"],
      h4: ["h4", "Baggage"], s1: ["s1", "Switch"], h5: ["h5", "Edge"]
    };

    function renderTopology(state) {
      const nodes = document.getElementById("nodes");
      const links = document.getElementById("links");
      nodes.innerHTML = "";
      links.innerHTML = "";

      const latestBySource = {};
      state.events.forEach((event) => {
        latestBySource[event.source] = event.action;
      });

      Object.entries(topologyPositions).forEach(([id, pos]) => {
        if (id !== "s1") {
          const action = latestBySource[id] || "IDLE";
          const switchPos = topologyPositions.s1;
          links.insertAdjacentHTML("beforeend", `
            <line x1="${pos.x}" y1="${pos.y}" x2="${switchPos.x}" y2="${switchPos.y}"
              stroke="${colors[action]}" stroke-width="10" stroke-linecap="round"
              opacity="0.85" filter="url(#glow)"></line>
          `);
        }
      });

      Object.entries(topologyPositions).forEach(([id, pos]) => {
        nodes.insertAdjacentHTML("beforeend", `
          <g transform="translate(${pos.x}, ${pos.y})">
            <circle r="${id === 's1' ? 46 : 38}" fill="white" stroke="#152033" stroke-width="3"></circle>
            <text text-anchor="middle" font-size="18" font-weight="700" y="-6">${labels[id][0]}</text>
            <text text-anchor="middle" font-size="14" y="16">${labels[id][1]}</text>
          </g>
        `);
      });
    }

    function renderStats(totals, rulesCount) {
      const stats = [
        ["Rules", rulesCount],
        ["Packets", totals.packet_count],
        ["Bytes", totals.total_bytes],
        ["STEER", totals.steered_packets],
        ["DROP", totals.dropped_packets]
      ];
      document.getElementById("stats").innerHTML = stats.map(([label, value]) => `
        <div class="stat"><div>${label}</div><b>${value}</b></div>
      `).join("");
    }

    function renderRules(rules) {
      document.getElementById("rulesTable").innerHTML = rules.map((rule) => `
        <tr>
          <td>${rule.intent.service}</td>
          <td><span class="pill ${rule.intent.action}">${rule.intent.action}</span></td>
          <td>${rule.intent.queue}</td>
          <td>${rule.intent.service_priority}</td>
          <td>${rule.intent.max_allowed_bandwidth} Gbps</td>
        </tr>
      `).join("");
    }

    function renderMetrics(metrics, hashToService) {
      document.getElementById("metricsTable").innerHTML = metrics.map((metric) => `
        <tr>
          <td>${hashToService[metric.key] || "unmatched-flow"}</td>
          <td><span class="pill ${metric.last_action}">${metric.last_action}</span></td>
          <td>${metric.packet_count}</td>
          <td>${metric.total_bytes}</td>
          <td>${(metric.drop_rate * 100).toFixed(1)}%</td>
          <td>${Object.entries(metric.queues).map(([queue, hits]) => `q${queue}:${hits}`).join(", ")}</td>
        </tr>
      `).join("");
    }

    function renderEvents(events) {
      document.getElementById("events").innerHTML = events.slice().reverse().map((event) => `
        <div class="event">
          <div>${new Date(event.timestamp * 1000).toLocaleTimeString()}</div>
          <div>${event.service}</div>
          <div>${event.source} → ${event.destination}</div>
          <div><span class="pill ${event.action}">${event.action}</span></div>
          <div>q${event.queue}</div>
        </div>
      `).join("");
    }

    async function refresh() {
      const res = await fetch("/api/state");
      const state = await res.json();
      const hashToService = {};
      state.rules.forEach((rule) => { hashToService[rule.key] = rule.intent.service; });
      renderStats(state.totals, state.rules.length);
      renderRules(state.rules);
      renderMetrics(state.metrics, hashToService);
      renderEvents(state.events);
      renderTopology(state);
      document.getElementById("updatedAt").textContent = new Date().toLocaleTimeString();
    }

    refresh();
    setInterval(refresh, 1000);
  </script>
</body>
</html>
"""


def _totals(metrics: list[dict]) -> dict[str, int]:
    totals = defaultdict(int)
    for metric in metrics:
        totals["packet_count"] += metric["packet_count"]
        totals["total_bytes"] += metric["total_bytes"]
        totals["dropped_packets"] += metric["dropped_packets"]
        totals["passed_packets"] += metric["passed_packets"]
        totals["steered_packets"] += metric["steered_packets"]
    return dict(totals)


@app.get("/")
def index() -> str:
    return render_template_string(HTML)


@app.get("/api/state")
def state() -> tuple[dict, int]:
    rules = [rule.to_dict() for rule in store.list_rules()]
    metrics = [metric.to_dict() for metric in store.list_metrics()]
    events = [event.to_dict() for event in store.list_events()][-40:]
    return {
        "rules": rules,
        "metrics": metrics,
        "events": events,
        "totals": _totals(metrics),
        "topology": TOPOLOGY,
    }, 200


@app.get("/api/topology")
def topology() -> tuple[dict, int]:
    return jsonify(TOPOLOGY)


def main() -> None:
    app.run(host="127.0.0.1", port=5002, debug=False)


if __name__ == "__main__":
    main()
