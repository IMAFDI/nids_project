import sys
import logging
from scapy.all import sniff, get_if_list, conf

logger = logging.getLogger('NIDS.PacketCapture')


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


def capture_packets(interface=None, count=100, timeout=30, packet_filter=None,
                    callback=None):
    """
    Capture packets from a network interface.

    Args:
        interface (str): Interface name. If None, uses system default.
        count (int): Number of packets to capture (0 = unlimited).
        timeout (int): Stop sniffing after this many seconds (None = no timeout).
        packet_filter (str): BPF filter string e.g. 'tcp', 'udp port 53'.
        callback (callable): Optional per-packet callback for real-time processing.

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
