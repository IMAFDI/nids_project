"""
NIDS CLI — Command Line Interface
Usage:
    python config/cli.py start [OPTIONS]
    python config/cli.py stop
    python config/cli.py configure
    python config/cli.py interfaces
"""

import os
import sys
import click

# Ensure config/ modules are importable
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, 'config'))


@click.group()
def cli():
    """NIDS — Network Intrusion Detection System"""
    pass


@cli.command()
@click.option('-i', '--interface', default=None, show_default=True,
              help='Network interface to sniff on (default: system default).')
@click.option('-c', '--count', default=200, show_default=True,
              help='Number of packets to capture per batch.')
@click.option('-t', '--timeout', default=60, show_default=True,
              help='Capture timeout in seconds.')
@click.option('-f', '--filter', 'bpf_filter', default=None,
              help="BPF packet filter e.g. 'tcp' or 'not arp'.")
@click.option('--live', is_flag=True, default=False,
              help='Process packets in real-time as they arrive.')
@click.option('--dashboard', is_flag=True, default=False,
              help='Launch the web dashboard alongside the NIDS.')
@click.option('--dashboard-port', default=5000, show_default=True,
              help='Port for the web dashboard.')
def start(interface, count, timeout, bpf_filter, live, dashboard, dashboard_port):
    """Start the NIDS and begin capturing/analysing traffic."""
    from main import run_nids
    click.echo(click.style("Starting NIDS...", fg='green', bold=True))
    if dashboard:
        click.echo(click.style(f"Web dashboard → http://localhost:{dashboard_port}", fg='cyan'))
    run_nids(
        interface=interface,
        packet_count=count,
        timeout=timeout,
        packet_filter=bpf_filter,
        live=live,
        dashboard=dashboard,
        dashboard_port=dashboard_port,
    )


@cli.command()
def stop():
    """Stop a running NIDS process (sends SIGTERM to the process group)."""
    import signal
    import subprocess
    click.echo(click.style("Stopping NIDS...", fg='yellow'))
    # Find PIDs running main.py
    try:
        result = subprocess.check_output(
            ['pgrep', '-f', 'main.py'], text=True
        ).strip()
        pids = result.split('\n')
        for pid in pids:
            if pid:
                os.kill(int(pid), signal.SIGTERM)
                click.echo(f"  Sent SIGTERM to PID {pid}")
        click.echo(click.style("NIDS stopped.", fg='green'))
    except subprocess.CalledProcessError:
        click.echo("No running NIDS process found.")
    except Exception as e:
        click.echo(click.style(f"Error stopping NIDS: {e}", fg='red'))


@cli.command()
@click.option('--rules-file', default=None,
              help='Path to rules.json (default: config/rules.json).')
@click.option('--thresholds-file', default=None,
              help='Path to anomaly_thresholds.json.')
@click.option('--model-path', default=None,
              help='Path to anomaly_model.joblib.')
def configure(rules_file, thresholds_file, model_path):
    """Display current NIDS configuration."""
    import json
    cfg_dir = os.path.join(BASE_DIR, 'config')
    rules_file       = rules_file       or os.path.join(cfg_dir, 'rules.json')
    thresholds_file  = thresholds_file  or os.path.join(cfg_dir, 'anomaly_thresholds.json')
    model_path       = model_path       or os.path.join(BASE_DIR, 'models', 'anomaly_model.joblib')

    click.echo(click.style("\n=== NIDS Configuration ===", bold=True))

    click.echo(f"\n  Rules file     : {rules_file}")
    if os.path.exists(rules_file):
        with open(rules_file) as f:
            rules = json.load(f).get('rules', [])
        click.echo(f"  Rules loaded   : {len(rules)}")
        for r in rules:
            click.echo(f"    [{r['id']}] {r['description']}")
    else:
        click.echo(click.style("  ⚠  Rules file not found!", fg='red'))

    click.echo(f"\n  Thresholds file: {thresholds_file}")
    if os.path.exists(thresholds_file):
        with open(thresholds_file) as f:
            thresh = json.load(f)
        for k, v in thresh.items():
            click.echo(f"    {k}: {v}")
    else:
        click.echo(click.style("  ⚠  Thresholds file not found!", fg='red'))

    click.echo(f"\n  Model path     : {model_path}")
    if os.path.exists(model_path):
        click.echo(click.style("  ✔  Model file found.", fg='green'))
    else:
        click.echo(click.style(
            "  ⚠  Model file not found — run: python models/train_model.py", fg='red'
        ))

    click.echo()


@cli.command()
def interfaces():
    """List all available network interfaces."""
    from packet_capture import list_interfaces
    list_interfaces()


@cli.command()
@click.option('--port', default=5000, show_default=True, help='Dashboard port.')
@click.option('--host', default='127.0.0.1', show_default=True, help='Dashboard host.')
def dashboard(port, host):
    """Launch only the web dashboard (reads from existing DB, no capture)."""
    from dashboard import run_dashboard
    click.echo(click.style(f"Dashboard → http://localhost:{port}", fg='cyan', bold=True))
    run_dashboard(host=host, port=port)


@cli.command()
@click.option('--limit', default=20, show_default=True, help='Number of recent events to show.')
@click.option('--severity', default=None, help='Filter by severity: LOW|MEDIUM|HIGH|CRITICAL')
def events(limit, severity):
    """Print recent intrusion events from the database."""
    import sys
    sys.path.insert(0, BASE_DIR + '/config')
    from database import init_db, get_recent_events
    init_db()
    rows = get_recent_events(limit=limit, severity=severity)
    if not rows:
        click.echo("No events found.")
        return
    colours = {'LOW': 'blue', 'MEDIUM': 'yellow', 'HIGH': 'red', 'CRITICAL': 'magenta'}
    click.echo(f"\n{'Time (UTC)':<22} {'Sev':<10} {'Type':<12} {'Src IP':<18} {'Description'}")
    click.echo("─" * 100)
    for e in rows:
        sev = e.get('severity', '')
        click.echo(
            click.style(
                f"{(e.get('timestamp','')[:19]):<22} {sev:<10} "
                f"{(e.get('event_type','')):<12} {(e.get('src_ip') or '—'):<18} "
                f"{e.get('description','')[:60]}",
                fg=colours.get(sev, 'white')
            )
        )
    click.echo()


if __name__ == '__main__':
    cli()
