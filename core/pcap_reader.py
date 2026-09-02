from collections import Counter
from pathlib import Path

from scapy.error import Scapy_Exception
from scapy.layers.dot11 import Dot11, RadioTap
from scapy.layers.eap import EAPOL
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP
from scapy.utils import PcapReader


class PcapReadError(Exception):
    """PCAP dosyası okunamadığında oluşturulan özel hata."""


def read_pcap_summary(file_path: str) -> dict:
    """
    PCAP veya PCAPNG dosyasını belleğe tamamen yüklemeden okur
    ve temel trafik bilgilerini döndürür.
    """

    path = Path(file_path)

    if not path.exists():
        raise PcapReadError("Seçilen dosya bulunamadı.")

    if path.suffix.lower() not in {".pcap", ".pcapng"}:
        raise PcapReadError("Yalnızca .pcap ve .pcapng dosyaları desteklenir.")

    counters = Counter()
    first_timestamp = None
    last_timestamp = None

    try:
        with PcapReader(str(path)) as packet_reader:
            for packet in packet_reader:
                counters["total_packets"] += 1

                timestamp = float(packet.time)

                if first_timestamp is None:
                    first_timestamp = timestamp

                last_timestamp = timestamp

                if packet.haslayer(RadioTap):
                    counters["radiotap"] += 1

                if packet.haslayer(Dot11):
                    counters["wifi_frames"] += 1

                if packet.haslayer(EAPOL):
                    counters["eapol"] += 1

                if packet.haslayer(IP):
                    counters["ipv4"] += 1

                if packet.haslayer(TCP):
                    counters["tcp"] += 1

                if packet.haslayer(UDP):
                    counters["udp"] += 1

                if packet.haslayer(ICMP):
                    counters["icmp"] += 1

                if packet.haslayer(ARP):
                    counters["arp"] += 1

    except (Scapy_Exception, OSError, ValueError) as error:
        raise PcapReadError(
            f"PCAP dosyası okunamadı: {error}"
        ) from error

    if counters["total_packets"] == 0:
        raise PcapReadError("PCAP dosyasında okunabilir paket bulunamadı.")

    duration = 0.0

    if first_timestamp is not None and last_timestamp is not None:
        duration = max(0.0, last_timestamp - first_timestamp)

    return {
        "file_name": path.name,
        "file_path": str(path.resolve()),
        "file_size_mb": round(path.stat().st_size / (1024 * 1024), 2),
        "total_packets": counters["total_packets"],
        "capture_duration": round(duration, 3),
        "packets_per_second": round(
            counters["total_packets"] / duration, 2
        ) if duration > 0 else 0.0,
        "radiotap": counters["radiotap"],
        "wifi_frames": counters["wifi_frames"],
        "eapol": counters["eapol"],
        "ipv4": counters["ipv4"],
        "tcp": counters["tcp"],
        "udp": counters["udp"],
        "icmp": counters["icmp"],
        "arp": counters["arp"],
    }