/* -*- c++ -*-
 hdr_sr.h
 source route header
 */
#ifndef scdsr_hdr_h
#define scdsr_hdr_h

#include <assert.h>
#include <packet.h>
#include "scpath.h"
#include "ServiceStruct.h"

#define SCDSR_HDR_SZ 4		// size of constant part of hdr
#define MAX_ROUTE_ERRORS 3	// how many route errors can fit in one pkt?
//class SCPath;


struct scdsr_link_down {
	int addr_type; /* same as hdr_cmn in packet.h */
	nsaddr_t tell_addr; // tell this host
	nsaddr_t from_addr; // that from_addr host can no longer
	nsaddr_t to_addr; // get packets to to_addr host
};

/* ======================================================================
 SCDSR Packet Types
 ====================================================================== */
struct scdsr_route_request {
	int req_valid_; /* request header is valid? */
	int req_id_; /* unique request identifier */
	int req_ttl_; /* max propagation */

};
//The service content in header

/*
 * the header of service request. added by HSQ
 * */



struct scdsr_service_request{
	int sreq_valid;           //request header is valid?
	int sreq_id;              // the ID of the SREQ message
	int sreq_ttl;             // the ttl of SREQ message
	int sreq_hops;		  // the passed route length of SREQ message
	Time init_time;			//the time when we send out service request
	Time last_hop_time;		// time when last node send out the packet
	nsaddr_t source_node;          // the source node's address
	//Service next_function;
	float sum_delay;           // the sum delay of the passed service path
	float sum_cost;            // the sum cost of the passed service path
	float max_delay;           // the max allowed delay of the service request
};


struct scdsr_route_reply {
	int rep_valid_; /* reply header is valid? */
	int rep_rtlen_; /* # hops in route reply */
	struct scdsr_addr rep_addrs_[MAX_SR_LEN];
};

struct scdsr_route_error {
	int err_valid_; /* error header is valid? */
	int err_count_; /* number of route errors */
	struct scdsr_link_down err_links_[MAX_ROUTE_ERRORS];
};


struct scdsr_service_reply {
	int srep_valid_;
	int srep_id;
	int sreq_id;
	//nsaddr_t source_node;  // the sourceNode of SREQ, or the destination of SREP
	float sum_delay;  // the sum of delay of the discovered service path
	float sum_cost;   // the sum of cost of the discovered service path
	int srep_len;
	struct scdsr_addr srep_addrs_[MAX_SR_LEN];
};

enum SIMsgType {SI_INIT = 0, SI_INVO = 1, SI_REP = 2};
struct scdsr_service_invoke{
	int sin_valid_;
	int sin_id_;
	int sin_success_;
	SIMsgType sin_type_; //0:need to find route  1:invocatoin  2:reply
};









/* ======================================================================
 SCDSR Flow State Draft Stuff
 ====================================================================== */
struct scdsr_flow_error {
	nsaddr_t flow_src;
	nsaddr_t flow_dst;
	u_int16_t flow_id; /* not valid w/ default flow stuff */
};

struct scdsr_flow_header {
	int flow_valid_;
	int hopCount_;
	unsigned short flow_id_;
};

struct scdsr_flow_timeout {
	int flow_timeout_valid_;
	unsigned long timeout_; // timeout in seconds...
};

struct scdsr_flow_unknown {
	int flow_unknown_valid_;
	int err_count_;
	struct scdsr_flow_error err_flows_[MAX_ROUTE_ERRORS];
};

// default flow unknown errors
struct scdsr_flow_default_err {
	int flow_default_valid_;
	int err_count_;
	struct scdsr_flow_error err_flows_[MAX_ROUTE_ERRORS];
};

/* ======================================================================
 SCDSR Header
 ====================================================================== */
class hdr_scdsr {
private:
	int valid_; /* is this header actually in the packet?
	 and initialized? */
	int salvaged_; /* packet has been salvaged? */

	int num_addrs_;  // the number of the addresses. by HSQ
	int cur_addr_;   // the current address. by HSQ
	int service_count;
	int service_index;
	float sum_delay_;
	float sum_cost_;
	struct scdsr_addr addrs_[MAX_SR_LEN];
	struct Service service_comp_[MAX_SERVICE_COMP_SZ];
	struct scdsr_addr service_dest_[MAX_SERVICE_COMP_SZ];
	struct scdsr_route_request scdsr_request_;
	struct scdsr_route_reply scdsr_reply_;
	struct scdsr_route_error scdsr_error_;

	// service discovery and composition. by ZYM
	struct scdsr_service_request service_request_;
	struct scdsr_service_reply service_reply_;
	struct scdsr_service_invoke service_invoke_;

	struct scdsr_flow_header scdsr_flow_;
	struct scdsr_flow_timeout scdsr_ftime_;
	struct scdsr_flow_unknown scdsr_funk_;
	struct scdsr_flow_default_err scdsr_fdef_unk;
public:
	static int offset_; /* offset for this header */
	inline int& offset() {
		return offset_;
	}
/*
	inline static hdr_scdsr* access(const Packet* p,ServiceContent *service_content) {
		hdr_scdsr* srh=(hdr_scdsr*) p->access(offset_);
		srh->setServiceContent(service_content);
		return srh;
		//return (hdr_scdsr*) p->access(offset_);
	}//add by zym
*/
	inline static hdr_scdsr* access(const Packet* p) {

		return (hdr_scdsr*) p->access(offset_);
	}
	inline int& valid() {
		return valid_;
	}
	inline int& salvaged() {
		return salvaged_;
	}
	inline int& num_addrs() {
		return num_addrs_;
	}
	inline int& cur_addr() {
		return cur_addr_;
	}

	inline int valid() const {
		return valid_;
	}
	inline int salvaged() const {
		return salvaged_;
	}
	inline int num_addrs() const {
		return num_addrs_;
	}
	inline int cur_addr() const {
		return cur_addr_;
	}
	inline struct scdsr_addr* addrs() {
		return addrs_;
	}

	inline int& route_request() {
		return scdsr_request_.req_valid_;
	}
	inline int& rtreq_seq() {
		return scdsr_request_.req_id_;
	}
	inline int& max_propagation() {
		return scdsr_request_.req_ttl_;
	}

	/* ======================================================================
	 * // service info. by ZYM
	====================================================================== */

	inline Service* ServiceComp(){
		return service_comp_;
	}

	inline int& ServiceCount(){
		return service_count;
	}

	inline int& ServiceIndex(){
		return service_index;
	}

	inline scdsr_addr* ServiceDest(){
		return service_dest_;
	}

	inline float& sumDelay(){
		return sum_delay_;
	}

	inline float& sumCost(){
		return sum_cost_;
	}

/* ======================================================================
 * // service request. by ZYM
====================================================================== */

	inline int& serviceRequest() {
		return service_request_.sreq_valid;
	}

	inline int& sreqID(){
		return service_request_.sreq_id;
	}

	inline int& sreqTtl(){
		return service_request_.sreq_ttl;
	}

	inline int& sreqHopCount(){
		return this->num_addrs();
	}

	inline Time& sreqSendTime(){
		return service_request_.init_time;
	}

	inline Time& sreqLastHopTime(){
		return service_request_.last_hop_time;
	}

	inline nsaddr_t& sreqSourceNode(){
		return service_request_.source_node;
	}

	/*inline float& sreqSumDelay(){
		return service_request_.sum_delay;
	}

	inline float& sreqSumCost() {
		return service_request_.sum_cost;
	}
*/
	inline float& sreqMaxDelay() {
		return service_request_.max_delay;
	}



/* ======================================================================
// service reply. by ZYM
====================================================================== */

	inline int& serviceReply() {
		return service_reply_.srep_valid_;
	}

	inline int& srepID() {
		return service_reply_.srep_id;
	}

	inline int& srepReqID() {
		return service_reply_.sreq_id;
	}

	/*inline float& srepSumDelay() {
		return service_reply_.sum_delay;
	}

	inline float& srepSumCost() {
		return service_reply_.sum_cost;
	}*/

	inline int& srepLength(){
		return service_reply_.srep_len;
	}

	inline scdsr_addr* srepPath(){
		return service_reply_.srep_addrs_;
	}

/* ======================================================================
// Service Invocation. by ZYM
====================================================================== */
	inline int& serviceInvocation(){
		return service_invoke_.sin_valid_;
	}

	inline int& sinID(){
		return service_invoke_.sin_id_;
	}

	inline SIMsgType& sinType(){
		return service_invoke_.sin_type_;
	}

	inline int& sinSuccess(){
		return service_invoke_.sin_success_;
	}

/* ======================================================================
* //route reply
*====================================================================== */

	inline int& route_reply() {
		return scdsr_reply_.rep_valid_;
	}
	inline int& route_reply_len() {
		return scdsr_reply_.rep_rtlen_;
	}
	inline struct scdsr_addr* reply_addrs() {
		return scdsr_reply_.rep_addrs_;
	}

	inline int& route_error() {
		return scdsr_error_.err_valid_;
	}
	inline int& num_route_errors() {
		return scdsr_error_.err_count_;
	}
	inline struct scdsr_link_down* down_links() {
		return scdsr_error_.err_links_;
	}

	// Flow state stuff, ych 5/2/01
	inline int &flow_header() {
		return scdsr_flow_.flow_valid_;
	}
	inline u_int16_t &flow_id() {
		return scdsr_flow_.flow_id_;
	}
	inline int &hopCount() {
		return scdsr_flow_.hopCount_;
	}

	inline int &flow_timeout() {
		return scdsr_ftime_.flow_timeout_valid_;
	}
	inline unsigned long &flow_timeout_time() {
		return scdsr_ftime_.timeout_;
	}

	inline int &flow_unknown() {
		return scdsr_funk_.flow_unknown_valid_;
	}
	inline int &num_flow_unknown() {
		return scdsr_funk_.err_count_;
	}
	inline struct scdsr_flow_error *unknown_flows() {
		return scdsr_funk_.err_flows_;
	}

	inline int &flow_default_unknown() {
		return scdsr_fdef_unk.flow_default_valid_;
	}
	inline int &num_default_unknown() {
		return scdsr_fdef_unk.err_count_;
	}
	inline struct scdsr_flow_error *unknown_defaults() {
		return scdsr_fdef_unk.err_flows_;
	}

	inline int size() {
		int sz = 0;
		if (num_addrs_ || route_request() || route_reply() || route_error()
				|| flow_timeout() || flow_unknown() || flow_default_unknown()
				)
			sz += SCDSR_HDR_SZ;
		sz += 24 + (4 + sizeof(Service)) *ServiceCount();
		if (num_addrs_)
			sz += 4 * (num_addrs_ - 1);
		if (route_reply())
			sz += 5 + 4 * route_reply_len();
		if (route_request())
			sz += 8;
		if (serviceRequest())
			sz += 10*4;
		if (serviceReply())
			sz += 4*4+4*srepLength();
		if (serviceInvocation())
			sz += 12+sizeof(SIMsgType);
		if (route_error())
			sz += 16 * num_route_errors();
		if (flow_timeout())
			sz += 4;
		if (flow_unknown())
			sz += 14 * num_flow_unknown();
		if (flow_default_unknown())
			sz += 12 * num_default_unknown();

		if (flow_header())
			sz += 4;

		sz = ((sz + 3) & (~3)); // align...
		assert(sz >= 0);
#if 0
		printf("Size: %d (%d %d %d %d %d %d %d %d %d)\n", sz,
				(num_addrs_ || route_request() ||
						route_reply() || route_error() ||
						flow_timeout() || flow_unknown() ||
						flow_default_unknown()) ? SR_HDR_SZ : 0,
				num_addrs_ ? 4 * (num_addrs_ - 1) : 0,
				route_reply() ? 5 + 4 * route_reply_len() : 0,
				route_request() ? 8 : 0,
				route_error() ? 16 * num_route_errors() : 0,
				flow_timeout() ? 4 : 0,
				flow_unknown() ? 14 * num_flow_unknown() : 0,
				flow_default_unknown() ? 12 * num_default_unknown() : 0,
				flow_header() ? 4 : 0);
#endif

		return sz;
	}

	// End Flow State stuff

	inline nsaddr_t& get_next_addr() {
		assert(cur_addr_ < num_addrs_);
		return (addrs_[cur_addr_ + 1].addr);
	}

	inline int& get_next_type() {
		assert(cur_addr_ < num_addrs_);
		return (addrs_[cur_addr_ + 1].addr_type);
	}

	inline void append_addr(nsaddr_t a, int type) {
		assert(num_addrs_ < MAX_SR_LEN - 1);
		addrs_[num_addrs_].addr_type = type;
		addrs_[num_addrs_++].addr = a;
	}

	inline void init() {
		valid_ = 1;
		salvaged_ = 0;
		num_addrs_ = 0;
		cur_addr_ = 0;

		route_request() = 0;
		route_reply() = 0;
		route_reply_len() = 0;
		route_error() = 0;
		num_route_errors() = 0;
		serviceRequest() = 0;
		serviceReply() = 0;
		serviceInvocation()=0;
		flow_timeout() = 0;
		flow_unknown() = 0;
		flow_default_unknown() = 0;
		flow_header() = 0;
		// set index to 0; zym
	}

#if 0
#ifdef DSR_CONST_HDR_SZ
	/* used to estimate the potential benefit of removing the
	 scdsrc route in every packet */
	inline int size() {
		return SR_HDR_SZ;
	}
#else
	inline int size() {
		int sz = SR_HDR_SZ +
		4 * (num_addrs_ - 1) +
		4 * (route_reply() ? route_reply_len() : 0) +
		8 * (route_error() ? num_route_errors() : 0);
		assert(sz >= 0);
		return sz;
	}
#endif // DSR_CONST_HDR_SZ
#endif // 0
	void dump(char *);
	char* dump();
};

#endif // scdsr_hdr_h
