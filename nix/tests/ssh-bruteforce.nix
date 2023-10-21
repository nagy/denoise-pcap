{ wireshark-cli, openssh, passh, variation ? 1, ... }:
let
  markerBenign = ''server.succeed("ping -s 100 -c 1 client_legit")'';
  markerMalicious = ''server.succeed("ping -s 201 -c 1 client_legit")'';
in {
  name = "ssh-bruteforce-var${toString variation}";
  passthru.filterName = "is_ssh_bruteforce";

  nodes.server = {
    services.openssh.enable = true;
    networking.firewall.allowedTCPPorts = [ 22 ];
    systemd.services.capture = {
      wantedBy = [ "network.target" ];
      serviceConfig.ExecStart = ''
        ${wireshark-cli}/bin/tshark -i eth1 -w /var/lib/capture.pcap
      '';
    };
  };
  nodes.client_legit = { environment.systemPackages = [ openssh ]; };
  nodes.client_attacker = { environment.systemPackages = [ passh ]; };

  testScript = ''
    import random
    random.seed(${toString variation})
    start_all()
    server.wait_for_unit("sshd.service")

    # we authenticate a legit client with the server
    client_legit.succeed('ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""')
    public_key = client_legit.succeed("ssh-keygen -y -f /root/.ssh/id_ed25519")
    public_key = public_key.strip()
    client_legit.succeed("chmod 600 /root/.ssh/id_ed25519")
    server.succeed("mkdir -m 700 /root/.ssh")
    server.succeed("echo '{}' > /root/.ssh/authorized_keys".format(public_key))
    # generate some authenticated ssh traffic
    ${markerBenign}
    for i in range( random.randint(1,10) ):
      randomEcho = "".join((random.choice("abcdefghijklmnopqrstuvwxyz1234567890") for i in range( random.randint(1,10) )))
      client_legit.succeed(f"ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no server 'echo hello{randomEcho}' >&2")

    # attempt to brute force via password
    ${markerMalicious}
    for i in range( random.randint(1,10) ):
      randompw = "".join((random.choice("abcdefghijklmnopqrstuvwxyz1234567890") for i in range( random.randint(1,10) )))
      client_attacker.fail(f"passh -p {randompw} ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no server")

    server.sleep(10) # needed for tshark
    server.systemctl("stop capture.service")
    server.copy_from_vm("/var/lib/capture.pcap")
  '';
}
