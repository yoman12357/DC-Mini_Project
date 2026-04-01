from __future__ import annotations

from mininet.topo import Topo


class SlicingDemoTopo(Topo):
    """Mininet topology for demonstrating software-based network slicing."""

    def build(self) -> None:
        edge = self.addSwitch("s1")

        hosts = {
            "agv": ("h1", "10.0.0.1/24"),
            "plc": ("h2", "10.0.0.10/24"),
            "farm": ("h3", "10.0.0.30/24"),
            "baggage": ("h4", "10.0.0.40/24"),
            "service": ("h5", "10.0.0.2/24"),
        }

        for name, (host_id, ip_addr) in hosts.items():
            host = self.addHost(host_id, ip=ip_addr)

            # Emulate different service classes with different link profiles.
            if name == "plc":
                self.addLink(host, edge, cls=None, bw=50, delay="1ms", loss=0)
            elif name == "agv":
                self.addLink(host, edge, cls=None, bw=30, delay="5ms", loss=0.1)
            elif name == "farm":
                self.addLink(host, edge, cls=None, bw=10, delay="15ms", loss=0.5)
            elif name == "baggage":
                self.addLink(host, edge, cls=None, bw=20, delay="8ms", loss=0.2)
            else:
                self.addLink(host, edge, cls=None, bw=100, delay="1ms", loss=0)


topos = {"slicingdemo": SlicingDemoTopo}
