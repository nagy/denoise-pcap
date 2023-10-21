(eval-when-compile
  (require hyrule * :readers *)
  (require hype * :readers *))
(import .helper [IP]
        scapy.all [UDP])

(defn syn-gen [num]
  (/ (IP :src "0.0.0.1"
         :dst f"1.1.1.{num}"
         :time num)
     (UDP :sport 27015
          :dport 80)))

(defpipe/main [] %
  ;; four scan attempts
  (ap-map (syn-gen it) (range 4))
  ;; one answer
  (:chain [(/ (IP  :src "1.1.1.2" :dst "0.0.0.1" :time 4)
              (UDP :sport 80      :dport 27015 ))]))
