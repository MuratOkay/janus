package com.g120s.janus.virtualization;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import com.g120s.janus.model.VirtualMachine;
import com.g120s.janus.model.VirtualizationHost;

import java.util.List;
import java.util.regex.*;

public final class KvmDiscovery {
    public static VirtualizationHost discover(String ip, String user, String pass,
                                             List<VirtualMachine> sink) throws Exception {
        VirtualizationHost host = new VirtualizationHost();
        host.id = "kvm:" + ip; host.ip = ip; host.type = "kvm";
        try (SSHClient ssh = new SSHClient()) {
            ssh.loadKnownHosts();
            ssh.connect(ip, 22);
            ssh.authPassword(user, pass);
            String list = run(ssh, "virsh list --all --name 2>/dev/null || true");
            for (String dom : list.split("\\R")) {
                dom = dom.trim();
                if (dom.isEmpty()) continue;
                VirtualMachine vm = new VirtualMachine();
                vm.name = dom; vm.hostId = host.id;
                String xml = run(ssh, "virsh dumpxml " + dom + " 2>/dev/null || true");
                Matcher mac = Pattern.compile("<mac address='([0-9a-f:]{17})'").matcher(xml);
                if (mac.find()) { vm.mac = mac.group(1); host.vmMacs.add(vm.mac); }
                Matcher ifs = Pattern.compile("<source (?:bridge|network)='([^']+)'").matcher(xml);
                while (ifs.find()) vm.nics.add(ifs.group(1));
                sink.add(vm);
            }
            String nets = run(ssh, "ip -4 -o addr show 2>/dev/null || true");
            Matcher m = Pattern.compile("inet (\\d+\\.\\d+\\.\\d+\\.\\d+/\\d+)").matcher(nets);
            while (m.find()) host.managementNets.add(m.group(1));
            ssh.disconnect();
        }
        return host;
    }
    static String run(SSHClient ssh, String cmd) throws Exception {
        try (Session s = ssh.startSession()) {
            Session.Command c = s.exec(cmd);
            return IOUtils.readFully(c.getInputStream()).toString();
        }
    }
}