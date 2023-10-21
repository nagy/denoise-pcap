(require hyrule * :readers *)
(import scapy)

(defn IP [#** kwargs]
  "Modified constructor to allow time setting."
  (let [time (.pop kwargs "time"  0)
        p (scapy.all.IP #** kwargs)]
    (setv p.time time)
    p))
