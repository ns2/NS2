set val(chan)           Channel/WirelessChannel    ;# channel type
set val(prop)           Propagation/TwoRayGround   ;# radio-propagation model
set val(netif)          Phy/WirelessPhy            ;# network interface type
set val(mac)            Mac/802_11                 ;# MAC type
#set val(ifq)           Queue/DropTail/PriQueue    ;# interface queue type
set val(ifq)             CMUPriQueue
set val(ll)             LL                         ;# link layer type
set val(ant)            Antenna/OmniAntenna        ;# antenna model
set val(ifqlen)         50                         ;# max packet in ifq
set val(nn)             60                         ;# number of mobilenodes
set val(rp)             DSR                      ;# routing protocol
set val(x)              1000         ;# X dimens_ion of topography
set val(y)              1000         ;# Y dimens_ion of topography
set val(stop)  10      ;# time of simulation end

set ns_ [new Simulator]
set tracefd       [open scen-2-10.tr w]
$ns_ trace-all $tracefd
set namtracefd      [open scen-2-10.nam w]
   
$ns_ namtrace-all-wireless $namtracefd $val(x) $val(y)
proc stop {} {
    puts "the simulator is stoped"
    global ns_ tracefd namtracefd
    $ns_ flush-trace
    close $tracefd
    puts "tracefd seted well"
    close $namtracefd
    puts "nam seted well"
    exec nam scen-2-10.nam &
    exit 0
}
# set up topography object
set topo [new Topography]
$topo load_flatgrid $val(x) $val(y)
set god_ [create-god $val(nn)]
$ns_ node-config   -adhocRouting $val(rp) \
  -llType $val(ll) \
  -macType $val(mac) \
  -ifqType $val(ifq) \
  -ifqLen $val(ifqlen) \
  -antType $val(ant) \
  -propType $val(prop) \
  -phyType $val(netif) \
  -channelType $val(chan) \
  -topoInstance $topo \
  -agentTrace ON \
  -routerTrace ON \
  -macTrace ON \
  -movementTrace ON

set rng [new RNG]
$rng seed next-substream

for {set i 0} {$i < $val(nn)} {incr i} {
    set node_($i) [$ns_ node]
    $node_($i) set X_ [$rng uniform 100.0 900.0]
    $node_($i) set Y_ [$rng uniform 100.0 900.0]
    $node_($i) set Z_ 0.0 #flat ground
    $ns_ initial_node_pos $node_($i) 30
}
   
#for {set i 0} {$i < $val(nn) } { incr i } {
#set node_($i) [$ns_ node]
#$node_($i) random-motion 1  
#}




#  Create DSR Agent
#  rt_rq_max_period indicates maximum time between rt reqs
#  rt_rq_period indicates length of one backoff period
#  send_timeout indicates how long a packet can live in sendbuf
for {set i 0} {$i < $val(nn)} {incr i} {
    set dsr($i) [new Agent/DSRAgent]
    $dsr($i)  node $node_($i)
    $dsr($i) rt_rq_max_period 0.1
    $dsr($i) rt_rq_period 0.10
    $dsr($i) send_timeout 5
}
#$node_(0) set X_ 100
#$node_(0) set Y_ 300
#$node_(0) set Z_ 0
#$node_(0) addService 1

#$node_(1) set X_ 1300
#$node_(1) set Y_ 1300
#$node_(1) set Z_ 0
#$node_(1) addService 2

#$node_(2) set X_ 100
#$node_(2) set Y_ 500
#$node_(2) set Z_ 0
#$node_(2) addService 3
#$node_(3) addService 3
#$node_(4) addService 3
#$node_(3) set X_ 345
#$node_(3) set Y_ 500
#$node_(3) set Z_ 0
#$node_(3) addService 4
#$node_(3) addService 5

#$node_(4) set X_ 430
#$node_(4) set Y_ 500
#$node_(4) set Z_ 0
#$node_(4) addService 6

#$node_(5) set X_ 500
#$node_(5) set Y_ 700
#$node_(5) set Z_ 0
#$node_(5) addService 7


#$node_(6) set X_ 700
#$node_(6) set Y_ 700
#$node_(6) set Z_ 0
#$node_(6) addService 8
#$node_(7) set X_ 500
#$node_(7) set Y_ 500
#$node_(7) set Z_ 0
#$node_(8) set X_ 700
#$node_(8) set Y_ 500
#$node_(8) set Z_ 0
#$node_(9) set X_ 900
#$node_(9) set Y_ 500
#$node_(9) set Z_ 0
#$node_(10) set X_ 100
#$node_(10) set Y_ 700
#$node_(10) set Z_ 0
#$node_(11) set X_ 300
#$node_(11) set Y_ 700
#$node_(11) set Z_ 0
#$node_(12) set X_ 500
#$node_(12) set Y_ 700
#$node_(12) set Z_ 0
#$node_(13) set X_ 700
#$node_(13) set Y_ 700
#$node_(13) set Z_ 0

#$node_(14) set X_ 900
#$node_(14) set Y_ 700
#$node_(14) set Z_ 0
#$node_(15) set X_ 100
#$node_(15) set Y_ 900
#$node_(15) set Z_ 0
#$node_(16) set X_ 300
#$node_(16) set Y_ 900
#$node_(16) set Z_ 0
#$node_(17) set X_ 500
#$node_(17) set Y_ 900s"
#$node_(17) set Z_ 0
#$node_(18) set X_ 700
#$node_(18) set Y_ 900
#$node_(18) set Z_ 0
#$node_(19) set X_ 900
#$node_(19) set Y_ 900
#$node_(19) set Z_ 0
#$node_(20) set X_ 100
#$node_(20) set Y_ 1100
#$node_(20) set Z_ 0
#$node_(21) set X_ 300
#$node_(21) set Y_ 1100
#$node_(21) set Z_ 0
#$node_(22) set X_ 500
#$node_(22) set Y_ 1100
#$node_(22) set Z_ 0
##$node_(23) set X_ 700
#$node_(23) set Y_ 1100
#$node_(23) set Z_ 0
#$node_(24) set X_ 900
#$node_(24) set Y_ 1100
#$node_(24) set Z_ 0


#for {set i 0} {$i < $val(nn) } { incr i } {
# $node_($i) set-service $i
#}

#$ns_ at 0.5 "$node_(1) setdest 1800 300 300.0"
#$ns_ at 1 "$node_(12) setdest 1700 1700 150.0"
#$ns_ at 110.0 "$node_(11) setdest 1900 1900 150.0"
#$ns_ at 130.0 "$node_(22) setdest 1950 1950 150.0"

set udp_(0) [new Agent/UDP]
$ns_ attach-agent $node_(0) $udp_(0)
set null_(0) [new Agent/LossMonitor]
$ns_ attach-agent $node_(5) $null_(0)
set cbr_(0) [new Application/Traffic/CBR]
$cbr_(0) set packetSize_ 500
$cbr_(0) set interval_ 2
$cbr_(0) set random_ 0
$cbr_(0) set maxpkts_ 20000000
$cbr_(0) attach-agent $udp_(0)


#set udp_(1) [new Agent/UDP]
#$ns_ attach-agent $node_(1) $udp_(1)
#set null_(1) [new Agent/LossMonitor]
#$ns_ attach-agent $node_(3) $null_(1)
#set cbr_(1) [new Application/Traffic/CBR]
#$cbr_(1) set packetSize_ 500
#$cbr_(1) set interval_ 0.15
#$cbr_(1) set random_ 0
#$cbr_(1) set maxpkts_ 20000000
#$cbr_(1) attach-agent $udp_(1)


$ns_ connect $udp_(0) $null_(0)
#$ns_ at 0.1 "$cbr_(0) start"
$ns_ at 0.05 "$udp_(0) send 999 \"fs:6:f1:8.5\""

puts "the agent is seted"

 #Define node initial position in nam
#for {set i 0} {$i < $val(nn)} { incr i } {
# 30 defines the node size for nam
#$ns_ initial_node_pos $node_($i) 60
#}
 #Telling nodes when the simulation ends
for {set i 0} {$i < $val(nn) } { incr i } {
   $ns_ at $val(stop) "$node_($i) reset";
}
 #ending nam and the simulation
$ns_ at $val(stop) "$ns_ nam-end-wireless $val(stop)"
$ns_ at $val(stop) "stop"
$ns_ at $val(stop).01 "puts \"end simulation\" ; $ns_ halt"
puts "the simulator is seted well"
$ns_ run

