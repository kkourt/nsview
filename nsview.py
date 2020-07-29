#!/usr/bin/env python3

import json
import subprocess as sp
from pprint import pprint
import sys

class Links:
    def __init__(self, d):
        self.links = []
        self.links_by_ifindex = {}
        self.links_by_ifname = {}
        for link in d:
            self.links.append(link)
            ifindex = link["ifindex"]
            self.links_by_ifindex[ifindex] = link
            ifname = link["ifname"]
            self.links_by_ifname[ifname] = link

        assert len(self.links) == len(self.links_by_ifindex)
        assert len(self.links) == len(self.links_by_ifname)

class Namespaces:
    def __init__(self, d):
        self.namespaces = []
        self.namespaces_by_ns = {}
        self.namespaces_by_netnsid = {}
        for ns_info in d["namespaces"]:
            self.namespaces.append(ns_info)
            ns = ns_info["ns"]
            self.namespaces_by_ns[ns] = ns_info
            netnsid = ns_info["netnsid"]
            if netnsid != "unassigned":
                self.namespaces_by_netnsid[int(netnsid)] = ns_info
        assert len(self.namespaces) == len(self.namespaces_by_ns)
        # multiple might have an unisnged namespace
        #assert len(self.namespaces) == len(self.namespaces_by_netnsid)

    def set_links(self):
        for ns_info in self.namespaces:
            links = get_links(ns_info["nsfs"])
            ns_info["links"] = links

            try:
                bpf_progs = get_bpf_net_progs(ns_info["nsfs"])[0]
            except:
                continue

            for (ty,progl) in bpf_progs.items():
                for prog in progl:
                    link1 = links.links_by_ifname[prog["devname"]]
                    link2 = links.links_by_ifindex[prog["ifindex"]]
                    assert link1 == link2
                    progs = link1.get("bpf_progs", [])
                    progs.append({
                        "type": ty,
                        "kind": prog["kind"],
                        "name": prog["name"],
                    })
                    link1["bpf_progs"] = progs

    def set_namespaces(self):
        for ns_info in self.namespaces:
            namespaces = get_namespaces(ns_info)
            ns_info["children"] = namespaces



def get_bpf_net_progs(nsfs):
    cmd = "sudo $(which nsenter) -n%s $(which bpftool) -j net show" % (nsfs,)
    ip = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    if ip.returncode != 0:
        raise RuntimeError("cmd: %s failed (%d)\n%s" % (cmd, ip.returncode, ip.stderr.decode("utf-8")))
    txt = ip.stdout.decode("utf-8")
    bpf_progs = json.loads(txt)
    return bpf_progs

def get_links(nsfs):
    cmd = "sudo $(which nsenter) -n%s $(which ip) -j addr" % (nsfs,)
    ip = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    if ip.returncode != 0:
        raise RuntimeError("cmd: %s failed (%d)\n%s" % (cmd, ip.returncode, ip.stderr.decode("utf-8")))
    txt = ip.stdout.decode("utf-8")
    links = Links(json.loads(txt))
    return links


def get_namespaces(ns=None):
    if ns is None:
        prefix = "sudo"
    else:
        prefix = "sudo $(which nsenter) -n%s" % (ns["nsfs"])

    cmd = "%s $(which lsns) --json -t net" % (prefix,)
    lsns = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
    if lsns.returncode != 0:
        raise RuntimeError("cmd: %s failed (%d)\n%s" % (cmd, lsns.returncode, lsns.stderr.decode("utf-8")))
    txt = lsns.stdout.decode("utf-8")

    namespaces = Namespaces(json.loads(txt))
    if ns is None:
        namespaces.set_links()
        namespaces.set_namespaces()

    return namespaces

def write_dot(namespaces):
    with open("nsview.dot", 'w') as f:
        f.write("digraph G {\n")
        f.write("\tgraph [ rankdir=\"LR\" ]\n")
        for ns in namespaces.namespaces:
            f.write("\tsubgraph cluster_%s {\n"  % (ns["ns"],))
            f.write("\t\tlabel = \" namespace %s \"\n" %(ns["ns"],))

            for link in ns["links"].links:
                dotname = "%s-%s" % (ns["ns"], link["ifindex"])

                records = []
                dotlabel = "<<table border=\"1\" cellborder=\"0\" bgcolor=\"gray\"> "
                dotlabel += "<tr><td port=\"name\" bgcolor=\"black\"><font color=\"white\">%s</font></td></tr>" % (link["ifname"])
                for ai in link["addr_info"]:
                    dotlabel += "<tr><td align=\"left\">%s/%s</td></tr>" % (ai["family"],ai["local"])
                for prog in link.get("bpf_progs", []):
                    v = ("%s-%s-%s") % (prog["type"], prog["kind"], prog["name"])
                    dotlabel += "<tr><td align=\"left\">%s</td></tr>" % (v,)
                dotlabel += "</table>>"

                f.write("\t\t\"%s\" [\n"     % (dotname,))
                #f.write("\t\t\tlabel = \"%s\"\n" % (dotlabel, ))
                f.write("\t\t\tlabel = %s\n" % (dotlabel, ))
                #f.write("\t\t\tshape = record\n")
                f.write("\t\t\tshape = plaintext\n")
                f.write("\t\t]\n")

            f.write("\t}\n")

        existing_pairs = set()
        for src_namespace in namespaces.namespaces:
            for src_dev in src_namespace["links"].links:

                # link in the same namespace
                src_link = src_dev.get("link", None)
                # Ignore because it makes the graph unreadable
                src_link = None
                if src_link is not None:
                    dst_namespace = src_namespace
                    dst_dev = src_namespace["links"].links_by_ifname[src_link]
                    dotname_src = "%s-%s" % (src_namespace["ns"], src_dev["ifindex"])
                    dotname_dst = "%s-%s" % (dst_namespace["ns"], dst_dev["ifindex"])
                    if (dotname_dst, dotname_src) not in existing_pairs:
                        f.write("\t\"%s\":name -> \"%s\":name [dir=none, color=green]\n" % (dotname_src, dotname_dst))
                        existing_pairs.add((dotname_src, dotname_dst))
                    continue

                src_link_netnsid = src_dev.get("link_netnsid", None)
                src_link_ifidx = src_dev.get("link_index", None)
                if src_link_netnsid is None or src_link_ifidx is None:
                    continue

                dst_ns = src_namespace["children"].namespaces_by_netnsid[src_link_netnsid]["ns"]
                dst_namespace = namespaces.namespaces_by_ns[dst_ns]
                dst_dev = dst_namespace["links"].links_by_ifindex[src_link_ifidx]
                dotname_src = "%s-%s" % (src_namespace["ns"], src_dev["ifindex"])
                dotname_dst = "%s-%s" % (dst_namespace["ns"], dst_dev["ifindex"])
                if (dotname_dst, dotname_src) not in existing_pairs:
                    f.write("\t\"%s\":name -> \"%s\":name [dir=none, color=red]\n" % (dotname_src, dotname_dst))
                    existing_pairs.add((dotname_src, dotname_dst))

        f.write("}\n")

def main():
    nses = get_namespaces()
    write_dot(nses)

if __name__ == '__main__':
    main()
