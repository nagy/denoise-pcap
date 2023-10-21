(eval-when-compile
  (require hyrule * :readers *)
  (require hype * :readers *))

(import pytest
        os
        denoise_pcap [ignored? nmap-scan? Pcap]
        .pcap-simple-syn [main :as main-simple-syn]
        .pcap-datatransfer-with-rst [main :as main-datatransfer-with-rst]
        .pcap-simple-udp [main :as main-simple-udp]
        .pcap-ntp-attack [main :as main-ntp-attack])

;;; Synthetic
(eval-when-compile
  (defreader γ `(get golden     ~(.parse-one-form &reader)))
  (defreader Γ `(get golden.out ~(.parse-one-form &reader))))
(eval-when-compile
  (defmacro deftest [testname #* body]
    `(defn [(pytest.mark.golden_test ~(+ (hy.mangle testname) ".golden.yml"))]
       ~testname [golden]
       (import pprint [pformat :as repr])
       (import tempfile [NamedTemporaryFile])
       (import scapy.all [wrpcap])
       (setv packets (lfor pkt (~(hy.models.Symbol (.replace (str testname) "test-" "main-"))) pkt))
       (assert (= (len packets) #Γ"input_length"))
       (with [tmppcap (NamedTemporaryFile :suffix ".pcap" :delete False)]
         (print tmppcap.name)
         (wrpcap tmppcap packets)
         (setv packets (Pcap.from_file tmppcap.name))
         (setv ret (lfor x packets
                         :if (not (in x (list (ignored? x packets))))
                         x))
         (assert (= (len ret) #Γ"length"))
         (assert (= (str (type ret)) #Γ"str_type"))
         ~@body))))

(deftest test-simple-syn)
(deftest test-datatransfer-with-rst)
(deftest test-simple-udp)
(deftest test-ntp-attack)

;;; VM Captured traffic

;; This can serve as an additional test for nmap, but requires,
;; that the capture file is in the environment
;; (defn test-nmap []
;;   (setv packets (list (Pcap.from-file (os.getenv "TESTFILE_NMAP"))))
;;   (assert (> (len packets) 2000))
;;   (assert (any (lfor n packets n.nmap_http?)))
;;   (assert (any (lfor n packets n.nmap_ssh?)))
;;   (setv ret (lfor x packets
;;                   :if (and
;;                         (not (ignored? x packets))
;;                         (not (nmap-scan? x packets)))
;;                   x))
;;   (assert (< (len ret) 30)))
