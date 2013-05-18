/*
 * ServiceRequestor.cc
 *
 *  Created on: Apr 27, 2013
 *      Author: kenchy
 */
#include "ServiceRequestor.h"
ServiceRequestor::ServiceRequestor() {
	this->cur_index_ = 0;
	this->length_ = 0;
	this->max_delay_=0;
}

ServiceRequestor::~ServiceRequestor() {

}

void ServiceRequestor::addReqService(int serviceID, char function[]) {
	if(length_<MAX_SERVICE_COMP_SZ)
	this->service_comp_[length_].serviceID = serviceID;
	strcpy(this->service_comp_[length_].function, function);
	length_++;


}

ServiceRequestor::ServiceRequestor(ServiceRequestor* service_requestor) {
	this->cur_index_ = service_requestor->currIndex();
	this->length_ = service_requestor->length();
	this->max_delay_ = service_requestor->maxDelay();
	for (int i = 0; i < service_requestor->length(); i++)
		this->service_comp_[i] = service_requestor->ServiceComp()[i];
}

void ServiceRequestor::fillSR(struct hdr_scdsr* srh) {
	for (int i = 0; i < length_; i++)
		srh->ServiceComp()[i] = this->service_comp_[i];
	srh->ServiceIndex() = this->cur_index_;
	srh->ServiceCount() = this->length_;
	srh->sreqMaxDelay() = this->max_delay_;



}
