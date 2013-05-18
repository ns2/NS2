/*
 * scdsrpacket.h
 * This file is modified from srpacket.h by hsq
 //
 // Ported from CMU/Monarch's code, appropriate copyright applies.
 */

#ifndef _SCSRPACKET_H_
#define _SCSRPACKET_H_

#include <packet.h>
#include "hdr_scdsr.h"
#include "ServiceRequestor.h"
#include "scpath.h"



struct SCSRPacket {
	SCID dest;
	SCID src;
	Packet *pkt; /* the inner NS packet */
	SCPath route;
	SCPath service_path;
	ServiceRequestor* service_requestor;
	// route(srh) uses the path constructor SCPath(struct hdr_sr *srh). by hsq
	SCSRPacket(Packet *p, struct hdr_scdsr *srh) :
			pkt(p), service_path(srh), service_requestor(new ServiceRequestor()) {
	}
	SCSRPacket() :
			pkt(NULL) {
	}
};


//add by ZYM
struct ServicePath {
	SCPath service_path[MAX_SERVICE_COMP_SZ]; //Each path is stands for one service request
	Service service_comp[MAX_SERVICE_COMP_SZ];
	SCID service_dest[MAX_SERVICE_COMP_SZ];
	int len; //the whole length of the path
	int cur_addr;	// the index of the current srh addr
	int service_index; //which service are we looking for
	int service_count; //how many services are we going to find?
	ServicePath() {
		len = 0;
		cur_addr = 0;
		service_index = 0;
		service_count=0;
	}
	ServicePath(struct hdr_scdsr *srh) {
		len = srh->num_addrs();
		cur_addr = srh->cur_addr();
		service_index = srh->ServiceIndex();
		service_count = srh->ServiceCount();
		for (int i = 0; i < srh->ServiceCount(); i++) {
			service_comp[i] = srh->ServiceComp()[i];
			service_dest[i] = SCID(srh->ServiceDest()[i]);
		}
		if (srh->ServiceCount()) {
			if(srh->serviceRequest()||srh->sinType()==SI_INVO) {
				for (int i = 0, j = i, c = 0;;) {
					SCID cur_node = SCID(srh->addrs()[j]);
					if (c<service_index&&cur_node == service_dest[c]) {
						if (i == j) { //ex: [0,5,5] => {[0,0] [0,5] [5,5]}
							service_path[c].appendToPath(cur_node);
							service_path[c].appendToPath(cur_node);
						} else { //ex: [0,5] => [0,1,3,4,5]
							for (int k = i; k <= j; k++)
								service_path[c].appendToPath(
										SCID(srh->addrs()[k]));
						}
						c++;
						i = j;
					} else{
						j++;
						if(j>=srh->num_addrs()){
							for(int k=i;k<j;k++)
								service_path[c].appendToPath(SCID(srh->addrs()[k]));
							break;}
					}
				}
			}

		}

	}

	inline void resetIterator() {this->service_index=0;this->cur_addr=0;}
	inline void reset() {cur_addr=0;len=0;}
	inline void appendToServicePath(SCID net_id) {
		service_path[service_index].appendToPath(net_id);
		len++;
	}
	inline void appendToServicePath(SCID net_id,ServiceRequestor service_requestor) {
		service_comp[service_index]=service_requestor.getNextService();
		service_dest[service_index]=net_id;
		if(this->len==0)
			//special case [0] => [0,0]
			service_path[service_index].appendToPath(net_id);
		service_path[service_index].appendToPath(net_id);
		if (service_index < 1|| (service_index >= 1&&
				service_dest[service_index - 1]!= service_dest[service_index]))
			len++;
		if(service_index<(service_requestor.length()-1)) {
			service_index++;
			service_path[service_index].appendToPath(net_id);
		}

	}
	void getCurPathIndex(int& row,int& col){
		int c = 0;
		if(service_index>=service_count)
			row=service_count-1;
		else
			row=service_index;

		if(row==0)
			col=cur_addr;
		else{
			for (int i = 0; i < row; i++){
				if (service_path[i].Path()[0] != service_path[i].Path()[1])
					c += service_path[i].length() - 1;}
			col=cur_addr-c;
		}


	}


	void reverseInPlace(){
		int fp,bp;
		for(int i=0;i<service_count;i++){
			service_path[i].reverseInPlace();
		}
		if(service_count>1){
			SCPath tempPath;
			for(fp=0,bp=(service_count-1);fp<bp;fp++,bp--){
				tempPath=service_path[fp].copy();
				service_path[fp]=service_path[bp].copy();
				service_path[bp]=tempPath.copy();
			}
		}

	}
	/*
	 * combine path a with path b
	 * ex:[0,1,2],[2,5] => [0,1,2,5]
	 */
/*	SCPath concatenate(SCPath& path_a,SCPath& path_b){
		SCPath path=new SCPath();
		if(path_a.length()+path_b.length()<=MAX_SR_LEN){
			path.appendPath(path_a);
			path.appendPath(path_b);
		}
		return path;
	}*/
	inline bool full() {
		if (len >= MAX_SR_LEN)
			return true;
		else
			return false;
	}
	bool hasLoop(SCID net_id) {
		for (int i = 0; i < service_path[service_index].length(); i++)
			if (service_path[service_index].Path()[i] == net_id)
				return true;
		return false;
	}
	inline int length() {return len;}
	void fillSR(struct hdr_scdsr *srh) {
		//copy services dest to srh
		int fill_times=0;
		if(srh->serviceRequest())
			fill_times=service_index;
		else
			fill_times=service_count;

		for (int i = 0; i < fill_times; i++) {
			service_dest[i].fillSRAddr(srh->ServiceDest()[i]);
		}
		//copy service path to srh->addr
		int c = 0;
		srh->num_addrs() = 0;
		for (int i = 0; i <= fill_times; i++) {
			if (service_path[i].Path()[0] != service_path[i].Path()[1]) {
				if (i > 0)
					c = 1;
				for (int j = c; j < service_path[i].length(); j++)
					service_path[i].Path()[j].fillSRAddr(
							srh->addrs()[srh->num_addrs()++]);
			} else if (i == 0)
				service_path[i].Path()[0].fillSRAddr(
						srh->addrs()[srh->num_addrs()++]);

		}
	}

};



struct ServicePacket {
	SCID dest;
	SCID src;
	Packet *pkt; /* the inner NS packet */
	ServicePath service_route;
	SCPath route;
	ServiceRequestor service_requestor;
	ServicePacket(Packet *p, struct hdr_scdsr *srh) :
			pkt(p), service_route(srh),route(srh) {
		service_requestor = new ServiceRequestor();
		for (int i = 0; i < srh->ServiceCount(); i++) {
			service_requestor.ServiceComp()[i] = srh->ServiceComp()[i];
		}
		service_requestor.maxDelay() = srh->sreqMaxDelay();
		service_requestor.length() = srh->ServiceCount();
		service_requestor.currIndex() = srh->ServiceIndex();


	}
	ServicePacket() : pkt(NULL) {
	}

};

#endif  //_SCDSRPACKET_H_
