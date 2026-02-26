"""
NIDS — Real-Time Web Dashboard (Flask + Server-Sent Events)

Run:  python config/dashboard.py
Then open: http://localhost:5000

Features:
  - Live event feed via Server-Sent Events (SSE) — no polling needed
  - Summary stats cards (total, by severity, last 24 h)
  - Timeline chart (Chart.js) — events per hour over last 24 h
  - Top attacker IPs table
  - Full paginated event log with severity filter
  - Auto-refreshes every 5 s
"""

import os
import sys
import json
import queue
import threading
import logging
from datetime import datetime
from flask import Flask, Response, render_template_string, jsonify, request

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))

from database import init_db, get_recent_events, get_stats, DB_PATH

logger = logging.getLogger('NIDS.Dashboard')

app = Flask(__name__)

# SSE event queue (broadcast to all connected clients)
_sse_queue: queue.Queue = queue.Queue(maxsize=200)


def push_sse_event(event_dict: dict):
    """Push a new event to all SSE subscribers (called from NIDS threads)."""
    try:
        _sse_queue.put_nowait(event_dict)
    except queue.Full:
        pass  # Drop if no clients connected


# ---------------------------------------------------------------------------
# HTML Template (single-file SPA)
# ---------------------------------------------------------------------------
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>NIDS Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e;
    --low: #58a6ff; --medium: #d29922; --high: #f85149; --critical: #bc8cff;
    --green: #3fb950;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; }
  header { background: var(--surface); border-bottom: 1px solid var(--border);
           padding: 16px 32px; display: flex; align-items: center; gap: 16px; }
  header h1 { font-size: 1.4rem; }
  .badge { background: var(--green); color: #000; font-size: 0.7rem;
           padding: 2px 8px; border-radius: 12px; font-weight: 700; }
  .badge.off { background: #f85149; }
  main { padding: 24px 32px; max-width: 1400px; margin: 0 auto; }

  /* Stats cards */
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 24px; }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }
  .card .label { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
  .card .value { font-size: 2rem; font-weight: 700; margin-top: 6px; }
  .card.low .value    { color: var(--low);      }
  .card.medium .value { color: var(--medium);   }
  .card.high .value   { color: var(--high);     }
  .card.critical .value { color: var(--critical); }
  .card.total .value  { color: var(--text);     }
  .card.green .value  { color: var(--green);    }

  /* Layout */
  .row { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 24px; }
  @media(max-width:900px){ .row { grid-template-columns: 1fr; } }

  /* Panels */
  .panel { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .panel-header { padding: 14px 20px; border-bottom: 1px solid var(--border);
                  display: flex; justify-content: space-between; align-items: center; }
  .panel-header h2 { font-size: 0.9rem; font-weight: 600; }
  .panel-body { padding: 16px; }

  /* Filter */
  select { background: var(--bg); color: var(--text); border: 1px solid var(--border);
           border-radius: 4px; padding: 4px 8px; font-size: 0.8rem; cursor: pointer; }

  /* Event table */
  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th { color: var(--muted); text-align: left; padding: 8px 12px;
       border-bottom: 1px solid var(--border); font-weight: 500; font-size: 0.72rem;
       text-transform: uppercase; letter-spacing: .04em; }
  td { padding: 8px 12px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1c2128; }

  .sev { display: inline-block; padding: 2px 8px; border-radius: 12px;
         font-size: 0.7rem; font-weight: 700; }
  .sev-LOW      { background: #1f3d6e; color: var(--low);      }
  .sev-MEDIUM   { background: #4a3800; color: var(--medium);   }
  .sev-HIGH     { background: #4a1010; color: var(--high);     }
  .sev-CRITICAL { background: #2d1b4e; color: var(--critical); }

  /* Top sources */
  .source-row { display: flex; align-items: center; gap: 10px; margin-bottom: 10px; }
  .source-ip { font-family: monospace; font-size: 0.82rem; min-width: 130px; }
  .bar-wrap { flex: 1; background: #21262d; border-radius: 4px; height: 8px; overflow: hidden; }
  .bar { height: 8px; border-radius: 4px; background: var(--high); transition: width .4s; }
  .source-count { font-size: 0.75rem; color: var(--muted); min-width: 36px; text-align: right; }

  /* Live feed */
  #livefeed { max-height: 320px; overflow-y: auto; }
  .feed-item { padding: 8px 12px; border-bottom: 1px solid #21262d;
               font-size: 0.78rem; animation: fadein .4s; }
  @keyframes fadein { from { opacity:0; transform: translateY(-6px); } to { opacity:1; transform: none; } }
  .feed-time { color: var(--muted); margin-right: 8px; font-family: monospace; }

  /* Chart */
  .chart-wrap { position: relative; height: 220px; }

  /* Pagination */
  .pager { display: flex; gap: 8px; justify-content: center; margin-top: 12px; }
  .pager button { background: var(--surface); color: var(--text); border: 1px solid var(--border);
                  border-radius: 4px; padding: 4px 12px; cursor: pointer; font-size: 0.8rem; }
  .pager button:hover { background: #21262d; }
  .pager button:disabled { opacity: .4; cursor: default; }
</style>
</head>
<body>

<header>
  <span style="font-size:1.6rem;">🛡️</span>
  <h1>NIDS &mdash; Network Intrusion Detection</h1>
  <span class="badge" id="live-badge">● LIVE</span>
  <span style="margin-left:auto;font-size:0.78rem;color:var(--muted);" id="last-update">Connecting…</span>
</header>

<main>
  <!-- Stats cards -->
  <div class="cards" id="stat-cards">
    <div class="card total"><div class="label">Total Events</div><div class="value" id="s-total">—</div></div>
    <div class="card green"><div class="label">Last 24 h</div><div class="value" id="s-24h">—</div></div>
    <div class="card critical"><div class="label">Critical</div><div class="value" id="s-critical">—</div></div>
    <div class="card high"><div class="label">High</div><div class="value" id="s-high">—</div></div>
    <div class="card medium"><div class="label">Medium</div><div class="value" id="s-medium">—</div></div>
    <div class="card low"><div class="label">Low</div><div class="value" id="s-low">—</div></div>
  </div>

  <div class="row">
    <!-- Timeline chart -->
    <div class="panel">
      <div class="panel-header"><h2>📈 Events – Last 24 Hours</h2></div>
      <div class="panel-body"><div class="chart-wrap"><canvas id="timelineChart"></canvas></div></div>
    </div>

    <!-- Top sources -->
    <div class="panel">
      <div class="panel-header"><h2>🌐 Top Attacker IPs</h2></div>
      <div class="panel-body" id="top-sources">Loading…</div>
    </div>
  </div>

  <div class="row">
    <!-- Event log -->
    <div class="panel">
      <div class="panel-header">
        <h2>📋 Event Log</h2>
        <select id="sev-filter" onchange="loadEvents()">
          <option value="">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </div>
      <div class="panel-body" style="padding:0;">
        <table>
          <thead><tr>
            <th>Time (UTC)</th><th>Severity</th><th>Type</th>
            <th>Src IP</th><th>Dst IP</th><th>Description</th>
          </tr></thead>
          <tbody id="event-tbody"></tbody>
        </table>
        <div class="pager">
          <button id="prev-btn" onclick="changePage(-1)" disabled>← Prev</button>
          <span id="page-info" style="font-size:0.8rem;color:var(--muted);padding:4px 8px;"></span>
          <button id="next-btn" onclick="changePage(1)">Next →</button>
        </div>
      </div>
    </div>

    <!-- Live feed -->
    <div class="panel">
      <div class="panel-header"><h2>⚡ Live Feed</h2></div>
      <div class="panel-body" style="padding:0;"><div id="livefeed"></div></div>
    </div>
  </div>
</main>

<script>
// ── State ──
let currentPage = 0;
const PAGE_SIZE = 20;
let timelineChart = null;

// ── Stats + timeline ──
async function loadStats() {
  const r = await fetch('/api/stats');
  const s = await r.json();
  document.getElementById('s-total').textContent    = s.total ?? 0;
  document.getElementById('s-24h').textContent      = s.recent_24h ?? 0;
  document.getElementById('s-critical').textContent = s.critical ?? 0;
  document.getElementById('s-high').textContent     = s.high ?? 0;
  document.getElementById('s-medium').textContent   = s.medium ?? 0;
  document.getElementById('s-low').textContent      = s.low ?? 0;
  document.getElementById('last-update').textContent =
    'Updated ' + new Date().toLocaleTimeString();
  renderTimeline(s.timeline || []);
  renderTopSources(s.top_sources || []);
}

function renderTimeline(data) {
  const labels = data.map(d => d.hour.slice(11,16));
  const values = data.map(d => d.count);
  if (!timelineChart) {
    const ctx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets: [{ label: 'Events', data: values,
        backgroundColor: 'rgba(248,81,73,0.5)', borderColor: '#f85149',
        borderWidth: 1, borderRadius: 3 }] },
      options: { responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', maxTicksLimit: 12 }, grid: { color: '#21262d' } },
          y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' }, beginAtZero: true }
        }
      }
    });
  } else {
    timelineChart.data.labels = labels;
    timelineChart.data.datasets[0].data = values;
    timelineChart.update('none');
  }
}

function renderTopSources(sources) {
  const max = sources.length ? sources[0].count : 1;
  const el = document.getElementById('top-sources');
  if (!sources.length) { el.innerHTML = '<p style="color:var(--muted);font-size:.8rem">No data yet.</p>'; return; }
  el.innerHTML = sources.map(s => `
    <div class="source-row">
      <span class="source-ip">${s.src_ip}</span>
      <div class="bar-wrap"><div class="bar" style="width:${Math.round(s.count/max*100)}%"></div></div>
      <span class="source-count">${s.count}</span>
    </div>`).join('');
}

// ── Event log ──
async function loadEvents() {
  const sev = document.getElementById('sev-filter').value;
  const url = `/api/events?limit=500${sev ? '&severity='+sev : ''}`;
  const r = await fetch(url);
  const events = await r.json();
  renderEventTable(events);
}

let _allEvents = [];
function renderEventTable(events) {
  _allEvents = events;
  currentPage = 0;
  renderPage();
}

function renderPage() {
  const start = currentPage * PAGE_SIZE;
  const slice = _allEvents.slice(start, start + PAGE_SIZE);
  const tbody = document.getElementById('event-tbody');
  tbody.innerHTML = slice.map(e => `
    <tr>
      <td style="white-space:nowrap;font-family:monospace;font-size:.72rem">${(e.timestamp||'').replace('T',' ').slice(0,19)}</td>
      <td><span class="sev sev-${e.severity}">${e.severity}</span></td>
      <td style="color:var(--muted)">${e.event_type||''}</td>
      <td style="font-family:monospace">${e.src_ip||'—'}</td>
      <td style="font-family:monospace">${e.dst_ip||'—'}</td>
      <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap"
          title="${(e.description||'').replace(/"/g,'&quot;')}">${e.description||''}</td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;color:var(--muted);padding:24px">No events</td></tr>';

  const total = _allEvents.length;
  const totalPages = Math.ceil(total / PAGE_SIZE) || 1;
  document.getElementById('page-info').textContent =
    `Page ${currentPage+1} of ${totalPages}  (${total} events)`;
  document.getElementById('prev-btn').disabled = currentPage === 0;
  document.getElementById('next-btn').disabled = (currentPage + 1) >= totalPages;
}

function changePage(delta) {
  currentPage += delta;
  renderPage();
}

// ── Live feed (SSE) ──
const feed = document.getElementById('livefeed');
const badge = document.getElementById('live-badge');

function sevColour(sev) {
  return {LOW:'var(--low)',MEDIUM:'var(--medium)',HIGH:'var(--high)',CRITICAL:'var(--critical)'}[sev]||'var(--text)';
}

function connectSSE() {
  const es = new EventSource('/stream');
  es.onopen = () => { badge.textContent = '● LIVE'; badge.className = 'badge'; };
  es.onerror = () => { badge.textContent = '● OFFLINE'; badge.className = 'badge off';
                       setTimeout(connectSSE, 5000); es.close(); };
  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    if (ev.ping) return;
    const item = document.createElement('div');
    item.className = 'feed-item';
    item.innerHTML = `<span class="feed-time">${new Date().toLocaleTimeString()}</span>
      <span style="color:${sevColour(ev.severity)};font-weight:700">[${ev.severity}]</span>
      <span style="margin-left:6px">${ev.description || ev.raw_message || ''}</span>
      ${ev.src_ip ? `<span style="color:var(--muted);margin-left:6px;font-family:monospace">${ev.src_ip}</span>` : ''}`;
    feed.prepend(item);
    if (feed.children.length > 100) feed.lastChild.remove();
    // Refresh stats + table
    loadStats();
    loadEvents();
  };
}

// ── Init ──
loadStats();
loadEvents();
connectSSE();
setInterval(loadStats, 10000);
setInterval(loadEvents, 15000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template_string(DASHBOARD_HTML)


@app.route('/api/stats')
def api_stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events')
def api_events():
    try:
        limit    = int(request.args.get('limit', 200))
        severity = request.args.get('severity') or None
        events   = get_recent_events(limit=limit, severity=severity)
        return jsonify(events)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stream')
def stream():
    """Server-Sent Events endpoint — pushes new events in real time."""
    def event_generator():
        # Send a keepalive ping every 20 s to prevent proxy timeouts
        import time
        last_ping = time.time()
        while True:
            try:
                event = _sse_queue.get(timeout=20)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                # keepalive ping
                yield f"data: {json.dumps({'ping': True})}\n\n"
            except GeneratorExit:
                break

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':    'no-cache',
            'X-Accel-Buffering': 'no',   # Disable nginx buffering
        },
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Start the Flask dashboard server (call from a background thread)."""
    init_db()
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.WARNING)  # Suppress noisy Flask request logs
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s | %(levelname)s | %(message)s')
    p = argparse.ArgumentParser(description='NIDS Web Dashboard')
    p.add_argument('--host', default='0.0.0.0')
    p.add_argument('--port', type=int, default=5000)
    p.add_argument('--debug', action='store_true')
    args = p.parse_args()
    print(f"Dashboard running at http://localhost:{args.port}")
    run_dashboard(host=args.host, port=args.port, debug=args.debug)
