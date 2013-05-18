set val(chan)           Channel/WirelessChannel    ;# channel type
set val(prop)           Propagation/TwoRayGround   ;# radio-propagation model
set val(netif)          Phy/WirelessPhy            ;# network interface type
set val(mac)            Mac/802_11                 ;# MAC type
#set val(ifq)           Queue/DropTail/PriQueue    ;# interface queue type
set val(ifq)            CMUPriQueue
set val(ll)             LL                         ;# link layer type
set val(ant)            Antenna/OmniAntenna        ;# antenna model
set val(ifqlen)         50                         ;# max packet in ifq
set val(nn)             20                         ;# number of mobilenodes
set val(rp)             SCDSR                      ;# routing protocol
set val(x)              1800         ;# X dimens_ion of topography
set val(y)              1300         ;# Y dimens_ion of topography
set val(stop)  		5      ;# time of simulation end
set val(energymodel)    EnergyModel     ;
set val(initialenergy)  100            ;# Initial energy in Joules

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
  -movementTrace ON \
  -energyModel $val(energymodel) \
  -idlePower 1.0 \
  -rxPower 3.0 \
  -txPower 3.0 \
	  -sleepPower 0.01 \
	  -transitionPower 0.5 \
	  -transitionTime 0.005 \
  -initialEnergy $val(initialenergy) 


set rng [new RNG]
$rng seed next-substream
 #Define node initial position in nam
for {set i 0} {$i < $val(nn)} {incr i} {
    set node_($i) [$ns_ node]
#    $ns_ at [$rng uniform 0.1 0.6] "$node_($i) setdest [$rng uniform 0 1500] [$rng uniform 0 900] [$rng uniform 100 600]"
#    $node_($i) set X_ [$rng uniform 100.0 1700.0]
#    $node_($i) set Y_ [$rng uniform 50.0 950.0]
#    $node_($i) set Z_ 0.0 #flat ground
    $node_($i) addService $i 1.5 0.5
    $node_($i) color "green"
# 30 defines the node size for nam

}


#  Create DSR Agent
#  rt_rq_max_period indicates maximum time between rt reqs
#  rt_rq_period indicates length of one backoff period
#  send_timeout indicates how long a packet can live in sendbuf
for {set i 0} {$i < $val(nn)} {incr i} {
    set dsr($i) [new Agent/SCDSRAgent]
    $dsr($i)  node $node_($i)
    $dsr($i) rt_rq_max_period 1
    $dsr($i) rt_rq_period 0.3
    $dsr($i) send_timeout 5
}

$node_(0) set X_ 410
$node_(0) set Y_ 550
$node_(0) set Z_ 0
$node_(0) color "gold"
$ns_ at 0.0 "$node_(0) label \"(Max Delay 4)\""

$node_(1) set X_ 340
$node_(1) set Y_ 300
$node_(1) set Z_ 0
$node_(1) color "red"
$ns_ at 0.0 "$node_(1) label \"(s1 1 0.5)\""

$node_(2) set X_ 300
$node_(2) set Y_ 450
$node_(2) set Z_ 0

$node_(3) set X_ 250
$node_(3) set Y_ 600
$node_(3) set Z_ 0

$node_(4) set X_ 320
$node_(4) set Y_ 760
$node_(4) set Z_ 0

$node_(5) set X_ 560
$node_(5) set Y_ 470
$node_(5) set Z_ 0
$node_(5) addService 1 4.1 0.6
$node_(5) color "red"
$ns_ at 0.0 "$node_(5) label \"(s1 5 0.6)\""


$node_(6) set X_ 440
$node_(6) set Y_ 400
$node_(6) set Z_ 0

$node_(7) set X_ 620
$node_(7) set Y_ 590
$node_(7) set Z_ 0

$node_(8) set X_ 490
$node_(8) set Y_ 700
$node_(8) set Z_ 0

$node_(9) set X_ 580
$node_(9) set Y_ 780
$node_(9) set Z_ 0
$node_(9) addService 1 2 0.6
$node_(9) color "red"
$ns_ at 0.0 "$node_(9) label \"(s1 2 0.5)\""


$node_(10) set X_ 550
$node_(10) set Y_ 320
$node_(10) set Z_ 0

$node_(11) set X_ 720
$node_(11) set Y_ 400
$node_(11) set Z_ 0

$node_(12) set X_ 800
$node_(12) set Y_ 560
$node_(12) set Z_ 0

$node_(13) set X_ 680
$node_(13) set Y_ 700
$node_(13) set Z_ 0

$node_(14) set X_ 810
$node_(14) set Y_ 780
$node_(14) set Z_ 0

$node_(15) set X_ 930
$node_(15) set Y_ 680
$node_(15) set Z_ 0
$node_(15) addService 1 1.8 0.9
$node_(15) color "red"
$ns_ at 0.0 "$node_(15) label \"(s1 2 0.9)\""

$node_(16) set X_ 960
$node_(16) set Y_ 500
$node_(16) set Z_ 0

$node_(17) set X_ 900
$node_(17) set Y_ 350
$node_(17) set Z_ 0


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

for {set i 0} {$i < $val(nn)} {incr i} {
    $ns_ initial_node_pos $node_($i) 30

}


$ns_ at 0.2 "$node_(0) setdest 540 590 300.0"
$ns_ at 0.65 "$node_(6) setdest 250 400 420.0"

set udp_(0) [new Agent/UDP]
$ns_ attach-agent $node_(0) $udp_(0)
set null_(0) [new Agent/LossMonitor]
$ns_ attach-agent $node_(6) $null_(0)
set cbr_(0) [new Application/Traffic/CBR]
$cbr_(0) set packetSize_ 500
$cbr_(0) set interval_ 0.2
$cbr_(0) set random_ 0
$cbr_(0) set maxpkts_ 20000000
$cbr_(0) attach-agent $udp_(0)



$ns_ connect $udp_(0) $null_(0)
#$ns_ at 0.2 "$cbr_(0) start"


for {set i 0} {$i < 20} {incr i} {
set v [expr "0.2 * $i"]
$ns_ at $v "$udp_(0) send 900 \"fs:1:func6:4.1\"";
}

#$ns_ at 0.2 "$udp_(0) send 64 \"fs:1,5:f1:8.5\"";


puts "the agent is seted"

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

