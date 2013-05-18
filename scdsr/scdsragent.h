/*
 * scdsragent.h
 * This file is modified from dsragent.h in ns-2
 **/

#ifndef _SCDSRAgent_h
#define _SCDSRAgent_h

class SCDSRAgent;

#include <stdarg.h>

#include <object.h>
#include <agent.h>
#include <trace.h>
#include <packet.h>
#include <dsr-priqueue.h>
#include <mac.h>
#include <mobilenode.h>
#include <map>
#include "scpath.h"
#include "scsrpacket.h"
#include "routecache.h"
#include "requesttable.h"
#include "flowstruct.h"
using namespace std;
#define SC_BUFFER_CHECK 0.5	// seconds between buffer checks
#define SC_SI_WAIT_TIMEOUT 0.1 //seconds wait to send service invocation for the first time
#define SC_RREQ_JITTER 0.03	// seconds to jitter broadcast route requests
#define SC_REP_JITTER 0.03
#define SC_SEND_TIMEOUT 30.0	// # seconds a packet can live in sendbuf
#define SC_SEND_BUF_SIZE 64
#define SC_RTREP_HOLDOFF_SIZE 10

#define SC_GRAT_ROUTE_ERROR 0	// tell_addr indicating a grat route err

#define SCDSR_FILTER_TAP		/* process a packet only once via the tap */

class ArpCallbackClass;
struct RtRepHoldoff {
  SCID requestor;
  SCID requested_dest;
  int best_length;
  int our_length;
};

struct SendBufEntry {
  Time t;			// insertion time
  SCSRPacket p;
};

struct ServiceSendBufEntry {
  Time t;			// insertion time
  ServicePacket p;
};

struct GratReplyHoldDown {
  Time t;
  SCPath p;
};

class SCSendBufferTimer : public TimerHandler {
public:
  SCSendBufferTimer(SCDSRAgent *a) : TimerHandler() { a_ = a;}
  void expire(Event *e);
protected:
  SCDSRAgent *a_;
};

LIST_HEAD(SCDSRAgent_List, SCDSRAgent);

class SCDSRAgent : public Tap, public Agent {
public:

  virtual int command(int argc, const char*const* argv);
  virtual void recv(Packet*, Handler* callback = 0);

  // tap out all data packets received at this host and promiscously snoop
  // them for interesting tidbits
  void tap(const Packet *p);

  void Terminate(void);
	// called at the end of the simulation to purge all packets
  void sendOutBCastPkt(Packet *p);
  
  SCDSRAgent();
  ~SCDSRAgent();

private:

  Trace *logtarget;
  int off_mac_;
  int off_ll_;
  int off_ip_;
  int off_sr_;

  // will eventually need to handle multiple infs, but this is okay for
  // now 1/28/98 -dam
  SCID net_id, MAC_id;		// our IP addr and MAC addr
  NsObject *ll;		        // our link layer output 
  CMUPriQueue *ifq;		// output interface queue
  Mac *mac_;

  // extensions for wired cum wireless sim mode
  MobileNode *node_;
  int diff_subnet(SCID dest, SCID myid);
  
  // extensions for mobileIP
  NsObject *port_dmux_;    // my port dmux
  
#ifdef SCDSR_FILTER_TAP
#define TAP_CACHE_SIZE	1024
#define TAP_BITMASK	(TAP_CACHE_SIZE - 1)
  /*
   *  A cache of recently seen packets on the TAP so that I
   *  don't process them over and over again.
   */
  int tap_uid_cache[TAP_CACHE_SIZE];
#endif

  /******** internal state ********/
  SCRequestTable request_table;
  ServiceRequestTable sreq_table; //service request table. add by zym
  SCRouteCache *route_cache;
  SendBufEntry send_buf[SC_SEND_BUF_SIZE];
  ServiceSendBufEntry scsend_buf[SC_SEND_BUF_SIZE];
  SCSendBufferTimer send_buf_timer;
  int route_request_num;	// number for our next route_request
  int service_request_num;  // number for our next service_request
  int service_reply_num; 	// number for our next service_reply
  int service_invoke_num;	// number for our next service_invoke
  map<int,bool> request_invoke_state; //is this kind of reply been invoked?
  int num_heldoff_rt_replies;
  RtRepHoldoff rtrep_holdoff[SC_RTREP_HOLDOFF_SIZE]; // not used 1/27/98
  GratReplyHoldDown grat_hold[SC_RTREP_HOLDOFF_SIZE];
  int grat_hold_victim;

  /* for flow state ych 5/2/01 */
  SCFlowTable flow_table;
  SCARSTable  ars_table;

  bool route_error_held; // are we holding a rt err to propagate?
  SCID err_from, err_to;	 // data from the last route err sent to us 
  Time route_error_data_time; // time err data was filled in

  /****** internal helper functions ******/

  /* all handle<blah> functions either free or hand off the 
     p.pkt handed to them */
  void handlePktWithoutSR(SCSRPacket& p, bool retry);
  void handleServicePktWithoutSR(ServicePacket& p,bool retry=false);				//add by ZYM

  /* obtain a source route to p's destination and send it off */
  void handlePacketReceipt(SCSRPacket& p);
  void handleServicePktReceipt(ServicePacket& p);				//add by ZYM
  void handleForwarding(SCSRPacket& p);
  void handleForwarding(ServicePacket& p);						//add by ZYM
  void handleRouteRequest(SCSRPacket &p);
  void handleServiceRequest(ServicePacket &p);					//add by ZYM
  /* process a route request that isn't targeted at us */

  /* flow state handle functions ych */
  void handleFlowForwarding(SCSRPacket &p);
  void handleFlowForwarding(SCSRPacket &p, int flowidx);
  void handleDefaultForwarding(SCSRPacket &p);

  bool ignoreRouteRequestp(SCSRPacket& p);
  bool ignoreServiceRequest(ServicePacket& p);					//add by ZYM
  ServiceRequestor decodeMsg(char* msg);						//add by ZYM
  // assumes p is a route_request: answers true if it should be ignored.
  // does not update the request table (you have to do that yourself if
  // you want this packet ignored in the future)
  void sendOutServicePktWithRoute(ServicePacket& p, bool fresh=false, Time delay = 0.0);//add by ZYM
  void sendOutPacketWithRoute(SCSRPacket& p, bool fresh, Time delay = 0.0);
  // take packet and send it out packet must a have a route in it
  // fresh determines whether route is reset first
  // time at which packet is sent is scheduled delay secs in the future
  // pkt.p is freed or handed off
  void sendOutServiceReq(ServicePacket &p, int max_prop = MAX_SR_LEN);//add by ZYM
  void sendOutRtReq(SCSRPacket &p, int max_prop = MAX_SR_LEN);
  void sendOutServiceInvocation(ServicePacket &p);
  // turn p into a route request and launch it, max_prop of request is
  // set as specified
  // p.pkt is freed or handed off
  void getRouteForSReq(ServicePacket &p,bool refresh); 					//add by ZYM
  void getRouteForPacket(SCSRPacket &p, bool retry);
  /* try to obtain a route for packet
     pkt is freed or handed off as needed, unless in_buffer == true
     in which case they are not touched */

  void acceptRouteReply(SCSRPacket &p);
  void acceptServiceReply(ServicePacket &p);
  /* - enter the packet's source route into our cache
     - see if any packets are waiting to be sent out with this source route
     - doesn't free the p.pkt */

  void returnSrcRouteToRequestor(SCSRPacket &p);
  void returnServicePathToRequestor(ServicePacket &p); 			//add by ZYM
  void receiveFirstTimeFromServiceReply(ServicePacket &p);			//add by ZYM
  // take the route in p, add us to the end of it and return the
  // route to the sender of p
  // doesn't free p.pkt

  bool replyFromRouteCache(SCSRPacket &p);
  /* - see if can reply to this route request from our cache
     if so, do it and return true, otherwise, return false 
     - frees or hands off p.pkt i ff returns true */

  void processUnknownFlowError(SCSRPacket &p, bool asDefault);
  void processFlowARS(const Packet *packet);
  // same idea as below, but for unknown flow error

  void processBrokenRouteError(SCSRPacket& p);
  void processBrokenRouteError(ServicePacket& p);
  // take the error packet and proccess our part of it.
  // if needed, send the remainder of the errors to the next person
  // doesn't free p.pkt

  void sendUnknownFlow(SCSRPacket &p, bool asDefault, u_int16_t flowid = 0);

  void xmitFailed(Packet *pkt, const char* reason = "DROP_RTR_MAC_CALLBACK");
  void xmitFlowFailed(Packet *pkt, const char* reason = "DROP_RTR_MAC_CALLBACK");
  void xmitServiceFailed(Packet *pkt, const char* reason = "DROP_RTR_MAC_CALLBACK");
  /* mark our route cache reflect the failure of the link between
     srh[cur_addr] and srh[next_addr], and then create a route err
     message to send to the orginator of the pkt (srh[0]) 
     p.pkt freed or handed off */
  void undeliverableServicePkt(Packet *p, int mine);
  void undeliverablePkt(Packet *p, int mine);
  /* when we've got a packet we can't deliver, what to do with it? 
     frees or hands off p if mine = 1, doesn't hurt it otherwise */

  void dropSendBuff(SCSRPacket &p);
  void dropSendBuff(ServicePacket &p);
  // log p as being dropped by the sendbuffer in SCDSR agent
  
  void stickPacketInSendBuffer(SCSRPacket& p);
  void stickServicePacketInSendBuffer(ServicePacket& p);
  void sendBufferCheck();
  // see if any packets in send buffer need route requests sent out
  // for them, or need to be expired

  void sendRouteShortening(SCSRPacket &p, int heard_at, int xmit_at);
  void sendRouteShortening(ServicePacket &p, int heard_at, int xmit_at);
  // p was overheard at heard_at in it's SR, but we aren't supposed to
  // get it till xmit_at, so all the nodes between heard_at and xmit_at
  // can be elided.  Send originator of p a gratuitous route reply to 
  // tell them this.


  void testinit();
  void trace(char* fmt, ...);

  friend void SCXmitFailureCallback(Packet *pkt, void *data);
  friend void SCXmitFlowFailureCallback(Packet *pkt, void *data);
  friend void SCXmitServiceFailureCallback(Packet *pkt, void *data);
  friend int FilterFailure(Packet *p, void *data);
  friend class SCSendBufferTimer;

#if 0
  void scheduleRouteReply(Time t, Packet *new_p);
  // schedule a time to send new_p if we haven't heard a better
  // answer in the mean time.  Do not modify new_p after calling this
  void snoopForRouteReplies(Time t, Packet *p);
  
friend void RouteReplyHoldoffCallback(Node *node, Time time, EventData *data);
#endif //0

  /* the following variables are used to send end-of-sim notices to all objects */
public:
	LIST_ENTRY(SCDSRAgent) link;
	static SCDSRAgent_List agthead;
};

#endif // _SCDSRAgent_h
