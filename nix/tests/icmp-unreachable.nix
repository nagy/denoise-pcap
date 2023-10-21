{ wireshark-cli, variation ? 1, ... }:
let
  markerBenign = ''server.succeed("ping -s 100 -c 1 client")'';
  markerMalicious = ''server.succeed("ping -s 204 -c 1 client")'';
in {
  name = "icmp-unreachable";
  passthru.filterName = "is_icmp_unreachable";

  nodes.server = {
    services.httpd.enable = true;
    networking.firewall.rejectPackets = true;
    networking.firewall.allowedTCPPorts = [ 80 ];
    systemd.services.capture = {
      wantedBy = [ "network.target" ];
      serviceConfig.ExecStart = ''
        ${wireshark-cli}/bin/tshark -i eth1 -w /var/lib/capture.pcap
      '';
    };
  };
  nodes.client = { };

  testScript = ''
    import random
    random.seed(${toString variation})
    start_all()
    client.wait_for_unit("multi-user.target")
    server.wait_for_unit("httpd.service")
    server.sleep(10) # needed for tshark

    ${markerBenign}
    response = client.succeed("curl -s -fvvv server")
    assert "It works" in response

    ${markerMalicious}
    client.fail(f"curl -s server:{random.randint(81,32768)}/")

    server.sleep(10) # needed for tshark
    server.systemctl("stop capture.service")
    server.copy_from_vm("/var/lib/capture.pcap")
  '';
}
