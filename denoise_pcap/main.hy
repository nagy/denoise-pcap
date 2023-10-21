(eval-when-compile
  (require hyrule * :readers *))
(import sys
        os [getenv]
        tqdm [tqdm]
        pcap_utils *
        dataclasses [dataclass field]
        functools [cached-property cache])

(defmacro ap-takewhile [form xs] `(do (import itertools [takewhile]) (takewhile (fn [it] ~form) ~xs)))
(defmacro ap-dropwhile [form xs] `(do (import itertools [dropwhile]) (dropwhile (fn [it] ~form) ~xs)))

;; from https://docs.python.org/3/library/itertools.html#itertools-recipes
(defn first-true [iterable]
  (next (filter None iterable) False))

(defclass [(dataclass :frozen True)] Packet []
  #^ bytes data
  #^ float time
  #^ int linktype
  (setv #^ int index (field :compare False))
  (setv #^ str filename (field :compare False))
  (defn payload [self] (nth-packet-payload self.filename self.index))
  (defn [cached-property] saddr   [self] (packet-source-addr self.data self.linktype))
  (defn [cached-property] daddr   [self] (packet-destination-addr self.data self.linktype))
  (defn [cached-property] saddr-oct [self] (packet-source-addr-octets self.data self.linktype))
  (defn [cached-property] daddr-oct [self] (packet-destination-addr-octets self.data self.linktype))
  (defn [cached-property] ssocket [self] (packet-source-socket self.data self.linktype))
  (defn [cached-property] dsocket [self] (packet-destination-socket self.data self.linktype))
  (defn [cached-property] sport   [self] (packet-source-port self.data self.linktype))
  (defn [cached-property] dport   [self] (packet-destination-port self.data self.linktype))
  (defn [cached-property] tcp?    [self] (packet-is-tcp  self.data self.linktype))
  (defn [cached-property] udp?    [self] (packet-is-udp  self.data self.linktype))
  (defn [cached-property] icmp?   [self] (packet-is-icmp self.data self.linktype))
  (defn [cached-property] icmp-req? [self] (packet-is-icmp-echo-request self.data self.linktype))
  (defn [cached-property] icmp-res? [self] (packet-is-icmp-echo-response self.data self.linktype))
  (defn [cached-property] icmp-unreachable? [self] (packet-is-icmp-destination-unreachable self.data self.linktype))
  (defn [cached-property] icmp-unreachable-port [self] (packet-icmp-destination-unreachable-port self.data self.linktype))
  (defn [cached-property] ack?    [self] (packet-tcp-ack self.data self.linktype))
  (defn [cached-property] syn?    [self] (packet-tcp-syn self.data self.linktype))
  (defn [cached-property] fin?    [self] (packet-tcp-fin self.data self.linktype))
  (defn [cached-property] rst?    [self] (packet-tcp-rst self.data self.linktype))
  (defn __repr__ [self]   f"<P{(int self.index)} {(len self)} {self.ssocket} -> {self.dsocket}>")
  (defn [cache] __contains__ [self other]
    (in other self.data))
  (defn [cache] __len__ [self]
    (len (self.payload))))

(defclass Pcap [list]
  (defn from-file [filename]
    (let [ret (Pcap
                (lfor #(index #(data time linktype)) (enumerate (MyIterator filename))
                      (Packet data time linktype index filename)))]
      (setv ret.filename filename)
      ret))
  (defn [cached-property] tcp-nums [self]
    (let [tcp-segmenter (tcp-make)]
      (lfor p self
            (if p.tcp?
                (do
                  (tcp-add tcp-segmenter p.saddr-oct p.sport p.daddr-oct p.dport p.syn? (or p.fin? p.rst?) p.ack?)
                  (tcp-find tcp-segmenter p.saddr-oct p.sport p.daddr-oct p.dport))
                None))))
  (defn [cache] tcp-from-index [self index]
    (Pcap (lfor #(i p) (enumerate self) :if (= index (get self.tcp-nums i)) p)))
  (defn [cache] tcp-for-packet [self packet]
    (or (when (list.__contains__ self packet)
          (when (!= None (get self.tcp-nums (self.index packet)))
            (let [r (get self.tcp-nums (self.index packet))]
              (self.tcp-from-index r))))
        []))
  (defn [cached-property] duration [self]
    (match (len self)
           (| 0 1) 0.0
           _ (- (. (get self -1) time)
                (. (get self 0) time))))
  (defn [cache] __contains__ [self other]
    (match other
           (Packet) (list.__contains__ self other)
           bytes    (any (gfor p self (in other p)))))
  (defn __hash__ [self]
    ;; We can use the id as hash, since Pcap itself
    ;; is not used as elements of other lists. This is
    ;; only used to check for cached values.
    (hash (id self)))
  (defn __and__ [self other]
    (Pcap (lfor p self :if (in p other) p)))
  (defn __float__ [self]
    self.duration)
  (defn __truediv__ [self other]
    (if (= 0 (len other))
        (len self)
        (/ (len self) (len other))))
  (defn __sub__ [self other]
    (Pcap (lfor p self :if (not (in p other)) p)))
  (defn __repr__ [self]
    (if (hasattr self "filename")
        f"<Pcap {self.filename} {( (. (super) __repr__)) }>"
        f"<Pcap {( (. (super) __repr__)) }>")))

(defmacro deffilter[filtername extra-args doc #* body]
  `(defn ~filtername [pkt pkts ~@extra-args]
     ~doc
     ;; for debug
     ;; (Pcap)
     (as-> pkts %
           ~@body)))

(deffilter time-interval [[time 10]]
  "Packets that are TIME seconds younger and older."
  (ap-takewhile (< it.time (+ pkt.time time)) %)
  (ap-dropwhile (< it.time (- pkt.time time)) %))

(deffilter ip-exchange []
  "Has P been answered by P.dst"
  (ap-filter (and pkt.saddr pkt.daddr
                  (= it.daddr pkt.saddr)
                  (= it.saddr pkt.daddr)) %))

(deffilter port-exchange []
  "Has P been answered by P.dport"
  (ap-filter (and pkt.sport pkt.dport
                  (= it.dport pkt.sport)
                  (= it.sport pkt.dport)) %))

(deffilter no-reset []
  "No tcp reset"
  (ap-reject (or it.rst? pkt.rst?) %))

(deffilter ntp? []
  "Packet is ntp"
  (or (= pkt.sport 123) (= pkt.dport 123))
  (if % [pkt] []))

(deffilter time-before [[time 10]]
  "Packets until UNTIL-TIME, no earlier than FROM-TIME."
  (ap-takewhile (<= it.time pkt.time) %)
  (ap-dropwhile (< it.time (- pkt.time time)) %))

(deffilter ip-same-source []
  "All the same of the source ip"
  (ap-filter (= it.saddr pkt.saddr) %))

(deffilter ntp-repetitive? []
  "Ntp questions repeating needlessly."
  (time-before pkt %)
  (ip-same-source pkt %)
  (ntp? pkt %)
  (if % [pkt] []))

(deffilter nmap-found? []
  "Packet is nmap"
  (ap-filter (or (in b"GET /nmaplowercheck" it)
                 (in b"SSH-2.0-Nmap-SSH2-Hostkey" it)) %))

(deffilter answered? []
  "Packet is answered"
  (time-interval pkt %)
  (ip-exchange pkt %)
  (port-exchange pkt %)
  (no-reset pkt %))

(deffilter ignored? []
  "Packet is ignored"
  (answered? pkt %)
  (if (not (or pkt.tcp? pkt.udp?))
      ;; treat all non-tcp and non-udp as answered
      ;; except, if it is an icmp-unreachable packet
      (if pkt.icmp-unreachable? [pkt] [])
      ;;  otherwise, check if they have been answered.
      (if (any %) [] [pkt])))

(deffilter rejection-expressed? []
  "This packet does not want to be handled by the receiver"
  (if (or (in pkt (icmp-unreachable? pkt %)))
      [pkt] []))

(deffilter dns-unsolicited? []
  "Unrequested DNS answer"
  ;; This serves, as a rudimentary implementation for detecting
  ;; unsolicited dns answers. Better would be to parse the udp packet,
  ;; on whether or not it is actually a dns answer.
  (if (and pkt.udp?
           (or (= pkt.sport 53)
               (= pkt.dport 53)))
      (ignored? pkt %)
      %))

(deffilter icmp-unreachable? []
  "Packet is icmp-unreachable"
  (time-interval pkt %)
  (ip-filter pkt %)
  (if (or pkt.icmp-unreachable?
          (= (first-true (ap-map it.icmp-unreachable-port %)) pkt.dport))
      [pkt] []))

(deffilter ip-filter []
  "All the same of the source and dest ip"
  (ap-filter (and it.daddr it.saddr) %)
  (ap-filter (or
               ;; If either the source or the destination have a particular
               ;; property, then include them
               (and
                 (= it.daddr pkt.saddr)
                 (= it.saddr pkt.daddr))
               (and
                 (= it.daddr pkt.daddr)
                 (= it.saddr pkt.saddr))) %))

(deffilter port-filter []
  "All the same of the source and dest port"
  (ap-filter (and it.dport it.sport) %)
  (ap-filter (or
               ;; If either the source or the destination have a particular
               ;; property, then include them
               (and
                 (= it.dport pkt.sport)
                 (= it.sport pkt.dport))
               (and
                 (= it.dport pkt.dport)
                 (= it.sport pkt.sport))) %))

(deffilter nmap-scan? []
  "nmap scan"
  (time-interval pkt % 60)
  (ip-filter pkt %)
  (nmap-found? pkt %)
  (if (any %) [pkt] []))

(deffilter portscanner? []
  "This packet belongs to a portscanner"
  (if (or (in pkt (nmap-scan? pkt %)))
      [pkt] []))

(deffilter same-tcp []
  "same tcp"
  (ap-filter (and (= int (type pkt.tcp)) (= it.tcp pkt.tcp)) %))

(deffilter icmp-echo? []
  "icmp echo ?"
  (ap-filter (or pkt.icmp-req?
                 pkt.icmp-res?) %))

(deffilter ssh? []
  "Packet is ssh"
  (if (in b"SSH-2.0-OpenSSH" (%.tcp-for-packet pkt))
      % (Pcap [])))

(deffilter ssh-bruteforce? []
  "Packet is ssh bruteforce"
  (ssh? pkt %)
  (.tcp-for-packet % pkt)
  (let [num-84 (len (list (ap-filter (= (len it) 84) %)))]
    (if (> 2 num-84)
        []
        [pkt])))

(deffilter noise? []
  "Packet is noise"
  (if (or (in pkt (ignored? pkt %))
          (in pkt (ssh-bruteforce? pkt %))
          (in pkt (icmp-unreachable? pkt %))
          (in pkt (nmap-scan? pkt %)))
      [pkt] []))

(defn main [[argv sys.argv]]
  (setv infile (get argv 1))
  (setv outfile (get argv 2))
  (setv filter (or (get argv (slice 3 None) 0) "is_noise"))
  (if (in ":" filter)
      (let [#(module filt) (.split filter ":")]
        (setv filter (getattr (__import__ module) filt)))
      (setv filter (get (globals) filter)))
  (print "phase 1: scrape" :file sys.stderr)
  (setv pcap (Pcap.from-file infile))
  (setv ret [])
  (print "phase 2: decide" :file sys.stderr)
  (for [x (tqdm pcap)]
    (.append ret (not (in x (filter x pcap)))))
  (print "phase 3: write" :file sys.stderr)
  (write-pcap infile outfile ret))
