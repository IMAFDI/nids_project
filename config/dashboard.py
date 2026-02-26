"""
NIDS — Real-Time Web Dashboard (Flask + Server-Sent Events)
Template: config/templates/dashboard.html
Run standalone: python config/dashboard.py
"""

import os
import sys
import json
import queue
import threading
import logging
from datetime import datetime
from flask import Flask, Response, render_template, jsonify, request, make_response

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))

from database import (init_db, get_recent_events, get_stats, DB_PATH,
                      search_events, delete_event, clear_events, export_events_csv)

logger = logging.getLogger('NIDS.Dashboard')

# Global scanner reference — set by main.py when scanner is running
_scanner = None

def set_scanner(scanner):
    global _scanner
    _scanner = scanner

WHITELIST_FILE = os.path.join(BASE_DIR, 'config', 'whitelist.json')
TEMPLATE_DIR   = os.path.join(BASE_DIR, 'config', 'templates')

app = Flask(__name__, template_folder=TEMPLATE_DIR)
app.config['SECRET_KEY'] = 'nids-dashboard-secret'
app.config['JSON_SORT_KEYS'] = False

# SSE broadcast queue
_sse_queue: queue.Queue = queue.Queue(maxsize=500)


def push_sse_event(event_dict: dict):
    """Push a new event to all SSE subscribers."""
    try:
        _sse_queue.put_nowait(event_dict)
    except queue.Full:
        pass


def _load_whitelist():
    if os.path.exists(WHITELIST_FILE):
        try:
            with open(WHITELIST_FILE) as f:
                return json.load(f).get('ips', [])
        except Exception:
            pass
    return []


def _save_whitelist(ips):
    with open(WHITELIST_FILE, 'w') as f:
        json.dump({
            '_comment': 'Trusted IPs — alerts from these are suppressed.',
            'ips': ips
        }, f, indent=2)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return render_template('dashboard.html')


@app.route('/api/stats')
def api_stats():
    try:
        return jsonify(get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events')
def api_events():
    try:
        query      = request.args.get('q') or None
        severity   = request.args.get('severity') or None
        event_type = request.args.get('type') or None
        src_ip     = request.args.get('src_ip') or None
        limit      = int(request.args.get('limit', 50))
        offset     = int(request.args.get('offset', 0))
        events, total = search_events(
            query=query, severity=severity, event_type=event_type,
            src_ip=src_ip, limit=limit, offset=offset
        )
        return jsonify({'events': events, 'total': total,
                        'limit': limit, 'offset': offset})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/<int:event_id>', methods=['DELETE'])
def api_delete_event(event_id):
    try:
        delete_event(event_id)
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/clear', methods=['POST'])
def api_clear_events():
    try:
        clear_events()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/events/export')
def api_export_csv():
    try:
        csv_data = export_events_csv()
        resp = make_response(csv_data)
        resp.headers['Content-Type'] = 'text/csv'
        resp.headers['Content-Disposition'] = (
            f'attachment; filename=nids_events_'
            f'{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
        )
        return resp
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist', methods=['GET'])
def api_get_whitelist():
    return jsonify({'ips': _load_whitelist()})


@app.route('/api/whitelist', methods=['POST'])
def api_add_whitelist():
    try:
        ip = (request.json or {}).get('ip', '').strip()
        if not ip:
            return jsonify({'error': 'No IP provided'}), 400
        ips = _load_whitelist()
        if ip not in ips:
            ips.append(ip)
            _save_whitelist(ips)
        return jsonify({'ok': True, 'ips': ips})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/whitelist/<path:ip>', methods=['DELETE'])
def api_remove_whitelist(ip):
    try:
        ips = [x for x in _load_whitelist() if x != ip]
        _save_whitelist(ips)
        return jsonify({'ok': True, 'ips': ips})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices')
def api_devices():
    try:
        if _scanner is None:
            return jsonify({'devices': [], 'stats': {}, 'error': 'Scanner not running'})
        devices = _scanner.get_devices()
        stats   = _scanner.get_stats()
        return jsonify({'devices': devices, 'stats': stats})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/devices/<path:ip>')
def api_device(ip):
    try:
        if _scanner is None:
            return jsonify({'error': 'Scanner not running'}), 503
        dev = _scanner.get_device(ip)
        if dev is None:
            return jsonify({'error': 'Device not found'}), 404
        return jsonify(dev)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/stream')
def stream():
    """SSE endpoint — pushes new intrusion events in real time."""
    def event_generator():
        while True:
            try:
                event = _sse_queue.get(timeout=20)
                yield f"data: {json.dumps(event)}\n\n"
            except queue.Empty:
                yield f"data: {json.dumps({'ping': True})}\n\n"
            except GeneratorExit:
                break

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_dashboard(host='127.0.0.1', port=5000, debug=False):
    """Start the Flask dashboard (call from a background thread)."""
    os.makedirs(TEMPLATE_DIR, exist_ok=True)
    init_db()
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    app.run(host=host, port=port, debug=debug, use_reloader=False, threaded=True)


if __name__ == '__main__':
    import argparse
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s | %(levelname)s | %(message)s')
    p = argparse.ArgumentParser(description='NIDS Web Dashboard')
    p.add_argument('--host', default='127.0.0.1')
    p.add_argument('--port', type=int, default=5000)
    p.add_argument('--debug', action='store_true')
    args = p.parse_args()
    print(f"Dashboard running at http://localhost:{args.port}")
    run_dashboard(host=args.host, port=args.port, debug=args.debug)
