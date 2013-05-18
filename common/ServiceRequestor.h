/*
 * Service.h
 *
 *  Created on: Apr 27, 2013
 *      Author: kenchy
 */

#ifndef SERVICEREQUESTOR_H_
#define SERVICEREQUESTOR_H_


#include <string>
#include <string.h>
#include <iostream>
#include <assert.h>
#include "ServiceStruct.h"
#include "scdsr/hdr_scdsr.h"

/**the request service of any node*/
class ServiceRequestor {
protected:
	Service service_comp_[MAX_SERVICE_COMP_SZ];
	int length_;
	int cur_index_; // which service are we looking for
	float max_delay_;
public:
	ServiceRequestor();
	ServiceRequestor(ServiceRequestor* service_requestor);
	~ServiceRequestor();
//	ServiceRequestor(int serviceId,char *function,float delay,float cost);
	void addReqService(int serviceID, char function[]);
	void fillSR(struct hdr_scdsr *srh);
	Service& getNextService() {
		return service_comp_[cur_index_];
	}
	Service& getPreService(){
		if(cur_index_==0)
			return service_comp_[0];
		else
			return service_comp_[cur_index_-1];
	}
	inline Service* ServiceComp() {
		return service_comp_;
	}
	inline int& currIndex() {
		return this->cur_index_;
	}
	inline float& maxDelay() {
		return this->max_delay_;
	}
	inline int& length() {
		return this->length_;
	}

	//Service extractFromHdr(struct hdr_scdsr *sr_schdr);
	//void fillHdr(struct hdr_scdsr *sr_schdr);
};
#endif /* SERVICE_H_ */
