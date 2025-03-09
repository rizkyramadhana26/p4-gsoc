import ctypes
import docker
import re
import subprocess

from pyroute2 import IPRoute
from bcc import BPF

def print_event_xdp(cpu, data, size):
    event = b["events_xdp"].event(data)
    print(f"[{event.container_name.decode('utf-8')}] Receving packet from {event.source_label}, {'accepting' if event.decision != 0 else 'dropping'}...")

client = docker.from_env()
network = client.networks.get("p4-gsoc_flat_network")
host_iface = "br-" + network.attrs["Id"][:12]

#Writing the eBPF program dynamically for all container's interface
ebpf_code = ""

with open("ebpf/import.c", "r") as file:
    ebpf_code += file.read() + "\n"

with open("ebpf/host.c", "r") as file:
    ebpf_code += file.read() + "\n"

for i,container in enumerate(client.containers.list()):
    name = container.attrs['Config']['Labels']['com.docker.compose.service']
    name = re.sub(r'[^a-zA-Z]', '_', name)
    with open("ebpf/container.c", "r") as file:
        ebpf_code += file.read().replace('CONTAINER_NAME',name).replace('CONTAINER_LABEL',str(i+1)) + "\n"

bash_script = """
for container in $(sudo docker ps -q); do
    iflink=$(sudo docker exec -it $container sh -c 'cat /sys/class/net/eth0/iflink')
    iflink=$(echo $iflink | tr -d '\r')
    veth=$(grep -l $iflink /sys/class/net/veth*/ifindex)
    veth=$(echo $veth | sed -e 's;^.*net/\\(.*\\)/ifindex$;\\1;')
    echo $container:$veth
done
"""

result = subprocess.run(bash_script, shell=True, text=True, capture_output=True)

mapping = {}
for line in result.stdout.strip().split("\n"):
    id = line.split(":")[0]
    veth = line.split(":")[1]
    mapping[id] = veth

b = BPF(text=ebpf_code, cflags=["-w"])

#Attach the eBPF programm to host's interface
egress = b.load_func("tc_egress_HOST", BPF.SCHED_CLS)
ipr = IPRoute()
idx = ipr.link_lookup(ifname=host_iface)[0]
ipr.tc("add", "clsact", idx)
ipr.tc("add-filter", "bpf", idx, ":2", fd=egress.fd, name=egress.name,
        parent="ffff:fff3", action="ok", classid=1)
print(f"Name: HOST PID: -, IP: -, LABEL: 0")


#Attach the eBPF program to all container's interface
for i,container in enumerate(client.containers.list()):
    ns_path = container.attrs['NetworkSettings']['SandboxKey']
    name = container.attrs['Config']['Labels']['com.docker.compose.service']
    name = re.sub(r'[^a-zA-Z]', '_', name)
    pid = container.attrs['State']['Pid']
    ip = container.attrs['NetworkSettings']['Networks']['p4-gsoc_flat_network']['IPAddress']
    id = container.attrs['Id'][:12]
    ingress = b.load_func(f"xdp_ingress_{name}", BPF.XDP)
    egress = b.load_func(f"tc_egress_{name}", BPF.SCHED_CLS)
    b.attach_xdp(mapping[id], ingress, 0)
    ipr = IPRoute()
    idx = ipr.link_lookup(ifname=mapping[id])[0]
    ipr.tc("add", "clsact", idx)
    ipr.tc("add-filter", "bpf", idx, ":2", fd=egress.fd, name=egress.name,
            parent="ffff:fff3", action="ok", classid=1, direct_action=True)
    
    print(f"Name: {name} PID: {pid}, IP: {ip}, LABEL: {i+1}")

# Open the perf buffer
b["events_xdp"].open_perf_buffer(print_event_xdp) 

#Define access control here
access_control_map = b["access_control"]
access_rules = [
    ("HOST", "http_a"),
    ("http_a", "http_b"),
    ("http_b", "rpc_a"),
    ("http_b", "rpc_b"),
    ("http_a", "http_c"),
    ("http_c", "rpc_c"),
]

class KeyT(ctypes.Structure):
    _fields_ = [("src", ctypes.c_char * 7), ("dst", ctypes.c_char * 7)]


for src, dst in access_rules:
    key = KeyT()
    key.src = src.encode("utf-8")
    key.dst = dst.encode("utf-8")
    value = ctypes.c_uint32(1)
    access_control_map[key] = value

print("Monitoring incoming packets... Press Ctrl+C to exit.")
while True:
    try:
        b.perf_buffer_poll()
    except:
        ipr = IPRoute()
        for k,v in mapping.items():
            b.remove_xdp(v, 0)
            idx = ipr.link_lookup(ifname=v)[0]
            ipr.tc("del", "clsact", idx)
        idx = ipr.link_lookup(ifname=host_iface)[0]
        ipr.tc("del", "clsact", idx)
        print("Detaching eBPF programs...")
        break
