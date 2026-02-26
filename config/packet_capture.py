import sys
import signal
import logging
import threading
from scapy.all import sniff, get_if_list, conf

logger = logging.getLogger('NIDS.PacketCapture')

# Global stop event — set this to cleanly stop any running capture
_stop_event = threading.Event()


def list_interfaces():
    """Return and print all available network interfaces."""
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    print()
    return interfaces


def get_default_interface():
    """Return the system default interface."""
    return conf.iface


def stop_capture():
    """Signal any running capture loop to stop gracefully."""
    _stop_event.set()


def capture_packets(interface=None, count=100, timeout=30, packet_filter=None,
                    callback=None):
    """
    Capture a single batch of packets from a network interface.

    Args:
        interface    : Interface name. If None, uses system default.
        count        : Number of packets to capture (0 = unlimited until timeout).
        timeout      : Stop sniffing after this many seconds (None = no timeout).
        packet_filter: BPF filter string e.g. 'tcp', 'udp port 53'.
        callback     : Optional per-packet callback for real-time processing.

    Returns:
        list: Captured packets.
    """
    if interface is None:
        interface = get_default_interface()
        logger.info(f"No interface specified, using default: {interface}")

    available = get_if_list()
    if interface not in available:
        logger.error(
            f"Interface '{interface}' not found. Available: {available}"
        )
        logger.info("Tip: run list_interfaces() to see available interfaces.")
        sys.exit(1)

    logger.info(
        f"Starting packet capture on '{interface}' "
        f"[count={count}, timeout={timeout}s, filter='{packet_filter}']"
    )

    try:
        packets = sniff(
            iface=interface,
            count=count,
            timeout=timeout,
            filter=packet_filter,
            prn=callback,
            store=True,
        )
        logger.info(f"Captured {len(packets)} packets.")
        return packets
    except PermissionError:
        logger.error(
            "Permission denied. Run the NIDS with elevated privileges "
            "(sudo on Linux/macOS, Administrator on Windows)."
        )
        sys.exit(1)
    except Exception as e:
        logger.error(f"Packet capture failed: {e}")
        raise


def capture_live_forever(interface=None, packet_filter=None, callback=None,
                         batch_timeout=10):
    """
    Capture packets indefinitely in a continuous loop, restarting the sniffer
    every `batch_timeout` seconds. Runs until stop_capture() is called or
    a SIGINT/SIGTERM is received.

    Args:
        interface     : Interface name. If None, uses system default.
        packet_filter : BPF filter string.
        callback      : Per-packet callback invoked for every packet.
        batch_timeout : Seconds per sniff batch before restarting (keeps the
                        loop responsive to stop signals). Default: 10s.
    """
    if interface is None:
        interface = get_default_interface()
        logger.info(f"No interface specified, using default: {interface}")

    available = get_if_list()
    if interface not in available:
        logger.error(
            f"Interface '{interface}' not found. Available: {available}"
        )
        logger.info("Tip: run list_interfaces() to see available interfaces.")
        sys.exit(1)

    _stop_event.clear()

    # Handle Ctrl+C and SIGTERM gracefully
    def _signal_handler(sig, frame):
        logger.info("Stop signal received — shutting down capture...")
        _stop_event.set()

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    total_packets = 0
    batch_num = 0
    logger.info(
        f"Live capture started on '{interface}' "
        f"[filter='{packet_filter}', batch={batch_timeout}s] — running indefinitely."
    )

    while not _stop_event.is_set():
        try:
            batch_num += 1
            pkts = sniff(
                iface=interface,
                timeout=batch_timeout,
                filter=packet_filter,
                prn=callback,
                store=False,   # Don't accumulate in memory
                count=0,       # Unlimited within the batch timeout
                stop_filter=lambda p: _stop_event.is_set(),
            )
            total_packets += len(pkts) if pkts else 0
            logger.debug(
                f"Batch #{batch_num}: {len(pkts) if pkts else 0} packets "
                f"(total: {total_packets})"
            )
        except PermissionError:
            logger.error(
                "Permission denied. Run the NIDS with elevated privileges "
                "(sudo on Linux/macOS, Administrator on Windows)."
            )
            sys.exit(1)
        except Exception as e:
            if _stop_event.is_set():
                break
            logger.error(f"Capture error (will retry in 3s): {e}")
            import time
            time.sleep(3)   # Brief pause before retrying on error

    logger.info(
        f"Live capture stopped after {batch_num} batches, "
        f"{total_packets} total packets processed."
    )
