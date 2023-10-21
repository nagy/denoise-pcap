{ wireshark-cli, nmap, variation ? 1, ... }:
let
  markerBenign = ''server.succeed("ping -s 100 -c 1 client")'';
  markerMalicious = ''server.succeed("ping -s 203 -c 1 client")'';
in {
  name = "nmap-scan-var${toString variation}";
  passthru.filterName = "is_nmap_scan";

  nodes.server = {
    services.httpd.enable = true;
    services.openssh.enable = true;
    networking.firewall.allowedTCPPorts = [ 22 80 ];
    systemd.services.capture = {
      wantedBy = [ "network.target" ];
      serviceConfig.ExecStart = ''
        ${wireshark-cli}/bin/tshark -i eth1 -w /var/lib/capture.pcap
      '';
    };
  };
  nodes.client = { environment.systemPackages = [ nmap ]; };
  nodes.client_benign = { };

  testScript = ''
    import random
    random.seed(${toString variation})
    start_all()
    client.wait_for_unit("multi-user.target")
    client_benign.wait_for_unit("multi-user.target")
    server.wait_for_unit("httpd.service")
    server.sleep(10) # needed for tshark

    ${markerMalicious}
    client.succeed("nmap -A server")

    ${markerBenign}
    for i in range( random.randint(1,10) ):
      response = client_benign.succeed("curl -s -fvvv server")
      assert "It works" in response

    server.sleep(10) # needed for tshark
    server.systemctl("stop capture.service")
    server.copy_from_vm("/var/lib/capture.pcap")
  '';
}
