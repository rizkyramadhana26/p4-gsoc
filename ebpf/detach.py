from bcc import BPF
import docker
from pyroute2 import NetNS, IPRoute

try:
    client = docker.from_env()
    network = client.networks.get("p4-gsoc_flat_network")
    host_iface = "br-" + network.attrs["Id"][:12]

    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=host_iface)[0]
    ipr.tc("del", "clsact", idx)
except:
    pass

for i,container in enumerate(client.containers.list()):
    ns_path = container.attrs['NetworkSettings']['SandboxKey']
    id = container.attrs['Id'][:12]
    with NetNS(ns_path) as netns:
        idx = netns.link_lookup(ifname="eth0")[0]
        try:
            netns.tc("del", "clsact", idx)
        except:
            pass
