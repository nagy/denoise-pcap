(eval-when-compile
  (require hyrule * :readers *))
(import os [getenv]
        denoise-pcap *)

(defmain [_ infile nomarker benign malicious]
  (let [mode False lst []]
    (for [p (Pcap.from-file infile)]
      (when p.icmp-res?
        (setv mode
              (match (- (len p.data) 42) ; subtract ethernet header
                     100 :benign
                     200 :malicious
                     201 :malicious-tcp
                     202 :malicious-udp
                     203 :malicious-tcp-udp
                     204 :malicious-icmp-unreachable)))
      (lst.append
        (if (or p.icmp-res? p.icmp-req?)
           False
           (match mode
                  :malicious-tcp (if p.tcp? :malicious :benign)
                  :malicious-udp (if p.udp? :malicious :benign)
                  :malicious-tcp-udp (if (or p.tcp? p.udp?) :malicious :benign)
                  :malicious-icmp-unreachable (if (or p.tcp? p.icmp-unreachable?) :malicious :benign)
                  _ mode))))
    (write-pcap infile nomarker (lfor x lst (!= x False)))
    (write-pcap infile benign (lfor x lst (= x :benign)))
    (write-pcap infile malicious (lfor x lst (= x :malicious)))))
