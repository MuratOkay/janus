package com.g120s.janus.virtualization;

import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.common.IOUtils;
import net.schmizz.sshj.connection.channel.direct.Session;
import com.g120s.janus.model.VirtualMachine;
import com.g120s.janus.model.VirtualizationHost;

import java.util.*;
import java.util.regex.*;

public final class EsxiDiscovery {
    private static final Pattern VM_ROW = Pattern.compile(
            "^(\\d+)\\s+([^\\s]+)\\s+\\[.*?\\]\\s+(.*)$", Pattern.MULTILINE);
    // vim-cmd vmsvc/getallvms

    public static VirtualizationHost discover(VirtualizationHost host,
                                              String user, String pass,
                                              List<VirtualMachine> sink) throws Exception {
        try (SSHClient ssh = new SSHClient()) {
            ssh.loadKnownHosts();
            ssh.connect(host.ip, 22);
            ssh.authPassword(user, pass);

            String list = run(ssh, "vim-cmd vmsvc/getallvms 2>/dev/null || true");
            Matcher m = VM_ROW.matcher(list);
            while (m.find()) {
                String vmid = m.group(1);
                VirtualMachine vm = new VirtualMachine();
                vm.name = m.group(2);
                vm.hostId = host.id;
                String detail = run(ssh, "vim-cmd vmsvc/get.summary " + vmid +
                                       " 2>/dev/null | grep -Ei 'macAddress|guestFullName|powerState' || true");
                Matcher mac = Pattern.compile("macAddress\\s*=\\s*\"([0-9a-fA-F:]{17})\"")
                                     .matcher(detail);
                if (mac.find()) { vm.mac = mac.group(1).toLowerCase(); host.vmMacs.add(vm.mac); }
                Matcher os = Pattern.compile("guestFullName\\s*=\\s*\"([^\"]+)\"").matcher(detail);
                if (os.find()) vm.guestOs = os.group(1);
                Matcher ps = Pattern.compile("powerState\\s*=\\s*\"([^\"]+)\"").matcher(detail);
                if (ps.find()) vm.powerState = ps.group(1);
                sink.add(vm);
            }
            // Yönetim arayüzlerindeki subnetler → keşif için ek ağ
            String ifaces = run(ssh, "esxcli network ip interface ipv4 get 2>/dev/null || true");
            Matcher m2 = Pattern.compile("\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)\\s+").matcher(ifaces);
            while (m2.find()) host.managementNets.add(m2.group(1));
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