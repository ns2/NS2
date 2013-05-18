/*
 * service.h
 *
 *  Created on: Mar 19, 2013
 *      Author: root
 */

#ifndef SERVICEMANAGER_H_
#define SERVICEMANAGER_H_
#include <string>
#include <string.h>
#include <iostream>
#include <assert.h>
#include <list>
#include "ServiceRequestor.h"
#include "scdsr/scpath.h"
#include "scdsr/scsrpacket.h"


using namespace std;
#define MAX_SERVICE_CACHE_SIZE 30
class ServiceProvider {
protected:
	Service service_table_[Service_Table_Size];
	int service_count_;
	int net_id_;
	int curr_index_;

public:
	ServiceProvider();
	ServiceProvider(ServiceProvider*);
	~ServiceProvider();
	bool findService(ServiceRequestor* service_comp);
	int getServiceCount();
	int getNetId();
	int getCurrentIndex();
	Service* getServiceTable();
	float getDelayById(int id);
	float getCostById(int id);
	void addService(int serviceId, char *function, float delay, float cost);
	void setNetId(int net_id);
private:
	bool findService(int service_id);
};
struct CacheMember{
	Service service_comp[MAX_SERVICE_COMP_SZ];
	scdsr_addr service_dest[MAX_SERVICE_COMP_SZ];
	scdsr_addr path[MAX_SR_LEN];
	float sumDelay;
	float sumCost;
	int length;
	int service_count;
	float qos;
	CacheMember(){
		length=0;
		service_count=0;
		sumDelay=0;
		sumCost=0;
		qos=100;
	}
};

class ServiceCache {
protected:
	list<CacheMember> service_cache_;
	int cache_size;
public:
	ServiceCache();
	~ServiceCache();
	list<CacheMember> getCacheList();
	void showCacheList();
	void noticeDeadLink(SCID from_id,SCID to_id);
	bool findService(ServiceRequestor*,ServicePath&);
	void insert(struct hdr_scdsr *srh);
private:
	bool getEntry(struct hdr_scdsr* srh);
};

class ServiceManager {
protected:
	ServiceProvider* service_provider_;
	ServiceCache* service_cache_;
public:
	ServiceManager();
	~ServiceManager();
	ServiceProvider* getServiceProvider();
	ServiceCache* getServiceCache();
	float getServiceCostById(int id){return service_provider_->getCostById(id);}
	float getServiceDelayById(int id){return service_provider_->getDelayById(id);}
	void showServiceCacheList(){this->service_cache_->showCacheList();}
	int matchSelf(ServiceRequestor* service_requestor) {
		return service_provider_->findService(service_requestor);
	}
	bool findInCache(ServiceRequestor* service_requestor,ServicePath& service_path) {
		return service_cache_->findService(service_requestor,service_path);
	}  //match a servic or a service_group?

};

#endif /* SERVICE_H_ */
