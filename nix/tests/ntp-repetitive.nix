{ lib, wireshark-cli, variation ? 1, ... }:
let
  markerBenign = ''server.succeed("ping -s 100 -c 1 client")'';
  markerMalicious = ''server.succeed("ping -s 202 -c 1 client")'';
in {
  name = "ntp-repetitive";
  passthru.filterName = "is_ntp_repetitive";

  nodes.server = {
    services.openntpd = {
      enable = true;
      extraConfig = ''
        listen on *
      '';
      servers = [ ];
    };
    services.httpd.enable = true;
    networking.firewall.allowedTCPPorts = [ 80 ];
    networking.firewall.allowedUDPPorts = [ 123 ];
    systemd.services.capture = {
      wantedBy = [ "network.target" ];
      serviceConfig.ExecStart = ''
        ${wireshark-cli}/bin/tshark -i eth1 -w /var/lib/capture.pcap
      '';
    };
  };
  nodes.client = {
    services.timesyncd.enable = lib.mkForce true;
    services.timesyncd.servers = [ "server" ];

    systemd.services.pinger = {
      script = ''
        while sleep 0.5 ; do systemctl restart systemd-timesyncd || true; done
      '';
    };
  };

  testScript = ''
    import random
    random.seed(${toString variation})
    start_all()
    client.wait_for_unit("multi-user.target")
    server.wait_for_unit("multi-user.target")
    server.sleep(10) # needed for tshark
    ${markerBenign}
    urlPart = "".join((random.choice("abcdefghijklmnopqrstuvwxyz1234567890") for i in range( random.randint(1,10) )))
    response = client.succeed("curl -s -fvvv server/")
    assert "It works" in response
    client.fail(f"curl -s -fvvv server/{urlPart}")
    ${markerMalicious}
    client.systemctl("start pinger.service")
    server.sleep(10) # needed for tshark
    server.systemctl("stop capture.service")
    server.copy_from_vm("/var/lib/capture.pcap")
  '';
}
