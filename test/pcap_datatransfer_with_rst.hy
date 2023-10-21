(eval-when-compile
  (require hyrule * :readers *)
  (require hype * :readers *))
(import dataclasses [dataclass]
        .helper [IP]
        scapy.all [TCP])


(defclass [dataclass] machine []
  #^str ip
  "Host abstraction")

(defclass [dataclass] channel [list]
  #^machine client
  #^machine server
  #^int time
  (defn __post_init__ [self]
    (self.emit True :flags "S")
    (self.emit False :flags "SA" :ack 1)
    (self.emit True :flags "A" :seq 1 :ack 1))
  (defn __neg__ [self]
    "Close channel"
    (self.emit True :flags "FA" :ack 1 :seq 4)
    (self.emit False :flags "FA" :ack 5 :seq 1)
    (self.emit True :flags "A"  :ack 2 :seq 5))
  (defn __lshift__ [self data]
    "Emit data from client to server"
    (self.emit True data :flags "PA" :seq 1 :ack 1)
    (self.emit False :flags "A" :seq 1 :ack 4))
  (defn emit [self from-client [data ""] #** tcpkwargs]
    (self.append (/ (IP :src (if from-client self.client.ip self.server.ip)
                        :dst (if from-client self.server.ip self.client.ip)
                        :time (do (+= self.time 1) self.time))
                    (TCP :sport (if from-client 1000 80)
                         :dport (if from-client 80 1000) #** tcpkwargs) data))))

(defpipe/main [] %
  (doto (channel (machine "0.0.0.1")
                 (machine "1.1.1.1") 0)
        (<< "GET")
        (-)))
