(eval-when-compile
  (require hyrule * :readers *)
  (require hype * :readers *))
(import .helper [IP]
        scapy.all [UDP NTP])

(defpipe/main [] %
  ;; one ntp
  [(/ (IP  :src "1.1.1.1" :dst "0.0.0.1" :time 1)
      (UDP :sport 80      :dport 27015 )
      (NTP))
   (/ (IP  :src "0.0.0.1" :dst "1.1.1.1" :time 2)
      (UDP :sport 27015   :dport 80 )
      (NTP))])
