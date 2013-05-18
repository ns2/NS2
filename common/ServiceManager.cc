#include <ServiceManager.h>

ServiceManager::ServiceManager() {
	this->service_provider_ = new ServiceProvider();
	this->service_cache_ = new ServiceCache();
}

ServiceManager::~ServiceManager() {

}


ServiceProvider* ServiceManager::getServiceProvider() {
//	service_provider_=netService;
	return this->service_provider_;
}

ServiceProvider::ServiceProvider() {
	service_count_ = 0;
	net_id_ = -1;
	curr_index_ = 0;
}

Service* ServiceProvider::getServiceTable() {
	return this->service_table_;
}

void ServiceProvider::addService(int serviceId, char *function, float delay,
		float cost) {
	if(findService(serviceId)){
		return;
	}
	else{
	Service s;
	s.serviceID = serviceId;
	strcpy(s.function, function);
	s.delay=delay;
	s.cost=cost;
	this->service_table_[curr_index_] = s;
	this->service_count_++;
	if ((curr_index_ + 1) % Service_Table_Size == 0)
		curr_index_ = 0;
	else
		curr_index_++;
	}
}

float ServiceProvider::getDelayById(int id) {
	for (int j = 0; j < this->service_count_; j++) {
		if (this->service_table_[j].serviceID
				== id)
			return service_table_[j].delay;
	}
	return 0;
}

float ServiceProvider::getCostById(int id) {
	for (int j = 0; j < this->service_count_; j++) {
		if (this->service_table_[j].serviceID
				== id)
			return service_table_[j].cost;
	}
	return 0;
}

bool ServiceProvider::findService(int serviceId) {

	bool find=false;
	for(int i=0;i<this->service_count_;i++){
		if(this->service_table_[i].serviceID==serviceId){
			find=true;
			break;
		}

	}
	return find;

}


bool ServiceProvider::findService(ServiceRequestor* service_requestor) {
	bool find=false;
	for (int j = 0; j < this->service_count_; j++) {
		if (this->service_table_[j].serviceID
				== service_requestor->getNextService().serviceID) {
			find = true;
			break;
		}
	}
	return find;

}

ServiceProvider::~ServiceProvider() {
}

int ServiceProvider::getNetId() {
	return this->net_id_;
}

int ServiceProvider::getServiceCount() {
	return this->service_count_;
}

int ServiceProvider::getCurrentIndex() {
	return this->curr_index_;
}

//copy constructor
ServiceProvider::ServiceProvider(ServiceProvider* service_provider_) {
	for (int i = 0; i < service_provider_->getServiceCount(); i++) {
		this->service_table_[i] = service_provider_->service_table_[i];
	}
	this->service_count_ = service_provider_->getServiceCount();
	this->net_id_ = service_provider_->getNetId();
	this->curr_index_ = service_provider_->getCurrentIndex();
}

ServiceCache::ServiceCache() {

}

ServiceCache::~ServiceCache() {
}

ServiceCache* ServiceManager::getServiceCache() {
	return this->service_cache_;
}

void ServiceProvider::setNetId(int net_id) {
	this->net_id_ = net_id;
}



void ServiceCache::showCacheList() {
	list<CacheMember>::iterator iter;
	iter = service_cache_.begin();
	while (iter != service_cache_.end()) {
		printf("Service Composition:");
		for (int i = 0; i < (*iter).service_count; i++)
			printf("%d ", (*iter).service_comp[i].serviceID);
		printf("\n");
		printf("Service Destination:");
		for(int i=0;i < (*iter).service_count; i++)
			printf("%d ", (*iter).service_dest[i].addr);
		printf("\n");
		printf("Route:");
		for(int i=0;i<(*iter).length;i++){
			if(i==(*iter).length-1)
				printf("%d",(*iter).path[i].addr);
			else
				printf("%d->",(*iter).path[i].addr);
		}
		printf("\n");
		printf("QoS: %f,%f,%f\n",(*iter).qos,(*iter).sumDelay,(*iter).sumCost);
		iter++;
	}

}


bool ServiceCache::findService(ServiceRequestor* service_requestor,ServicePath& path ) {
	list<CacheMember>::iterator iter;
	bool find=false;
	bool match=false;
	float qos=-1;
	int old_len=path.cur_addr+1;
	int len_change=0;
	CacheMember salvage_path;
	for(iter = service_cache_.begin();iter != service_cache_.end();iter++)
	{
		match=true;
		//to see if we know where to invoke a service composition
		for (int i = service_requestor->currIndex(), j = 0;
				i < service_requestor->length(); i++, j++) {
			if ((*iter).service_comp[j].serviceID
					!= service_requestor->ServiceComp()[i].serviceID) {
				match = false;
				break;
			}
		}
		//if we do match, choose the path with the best qos
		if (match) {
			if ((*iter).qos > qos) {
				find = true;
				qos = (*iter).qos;
				salvage_path=(*iter);
			}
		}
	}

	if (find) {
		for (int c = service_requestor->currIndex(), i = 0;
				c < service_requestor->length(); c++, i++) {
			path.service_dest[c] = salvage_path.service_dest[i];
			service_requestor->ServiceComp()[c]=salvage_path.service_comp[i];
		}
		path.service_index = service_requestor->currIndex();
		path.service_count = service_requestor->length();
		int row, col;
		path.getCurPathIndex(row, col);
		// reset the rest of the route, because we will
		// replace them with a new route
		for(int c=col+1;c<path.service_path[row].length();c++)
			path.service_path[row].Path()[c]=SCID();
		for(int r=row+1;r<path.service_count;r++)
			path.service_path[r]=SCPath();
		path.service_path[row].length()=col+1;

		for (int c = 0; c < salvage_path.length;) {
			if (c == 0) {
				if (SCID(salvage_path.path[c]) != path.service_path[row].Path()[col]){
					path.service_path[row].Path()[col]=SCID(salvage_path.path[c]);
				}

				else
					c++;
			} else if (SCID(salvage_path.path[c])
					== path.service_dest[path.service_index]) {
				path.appendToServicePath(SCID(salvage_path.path[c]));
				len_change++;
				path.service_index++;
				if (path.service_index >= service_requestor->length())
					break;
				else if (path.service_dest[path.service_index]
						== path.service_dest[path.service_index - 1])
					path.appendToServicePath(SCID(salvage_path.path[c]));
				else {
					path.appendToServicePath(SCID(salvage_path.path[c++]));
				}
			} else {
				path.appendToServicePath(SCID(salvage_path.path[c++]));
				len_change++;
			}
		}
		//we recalculate the path length here.
		path.len = old_len + len_change;
		return true;
	} else
		return false;

}

void ServiceCache::noticeDeadLink(SCID from_id, SCID to_id) {
	list<CacheMember>::iterator iter;
	bool match = false;
	for (iter = service_cache_.begin(); iter != service_cache_.end();) {
	    match=false;
		for (int fp = 0, sp = 1; sp < (*iter).length; fp++, sp++) {
			if ((*iter).path[fp].addr == (int) from_id.addr
					&& (*iter).path[sp].addr == (int)to_id.addr){
				match = true;
				break;
			}
		}
		if(match)
		{
			iter=this->service_cache_.erase(iter);
		}
		else
			iter++;

	}
}

void ServiceCache::insert(struct hdr_scdsr* srh) {
	int hop_count=srh->cur_addr();
	if(getEntry(srh))
		return;
	if(srh->cur_addr()>0&&service_cache_.size()<MAX_SERVICE_CACHE_SIZE){
		CacheMember service_cache;
		for(int i=srh->cur_addr();i>=0;i--)
			service_cache.path[service_cache.length++]=srh->addrs()[i];
		int j=0;
		for(int i=srh->num_addrs()-1;i>=srh->cur_addr();i--){
			if(SCID(srh->addrs()[i])==SCID(srh->ServiceDest()[j]))
				j++;
		}
		for(;j<srh->ServiceCount();j++) {
			service_cache.service_comp[service_cache.service_count]=srh->ServiceComp()[j];
			service_cache.service_dest[service_cache.service_count]=srh->ServiceDest()[j];
			service_cache.sumDelay+=service_cache.service_comp[service_cache.service_count].delay;
			service_cache.sumCost+=service_cache.service_comp[service_cache.service_count].cost;
			service_cache.service_count++;
		}
		service_cache.qos = 100 -  service_cache.sumDelay
				- service_cache.sumCost - 0.1 * hop_count;
		this->service_cache_.push_back(service_cache);
	}
}

bool ServiceCache::getEntry(struct hdr_scdsr* srh) {
	float alpha=15;
	int hop_count=srh->cur_addr();
	list<CacheMember>::iterator iter;
	bool find=false;
	for (iter = service_cache_.begin(); iter != service_cache_.end();iter++) {
		bool route_match=true;
		bool service_match=true;
		bool dest_match=true;
		float sumDelay=0;
		float sumCost=0;
		//First to see if there exist a same route
		if ((*iter).length != srh->cur_addr() + 1)
			route_match = false;
		else {
			for (int i = srh->cur_addr(), j = 0; i >= 0; i--, j++)
				if ((*iter).path[j].addr != srh->addrs()[i].addr) {
					route_match = false;
					break;
				}
		}
		//If the route are the same, let's compare service destination and service composition
		if(route_match){
			int j=0;
			for(int i=srh->num_addrs()-1;i>=srh->cur_addr();i--){
				if(srh->addrs()[i].addr==srh->ServiceDest()[j].addr)
					j++;
			}
			if((*iter).service_count!=srh->ServiceCount()-j){
				service_match=false;
				dest_match=false;
			}
			else{

				for (int i = 0; j < srh->ServiceCount(); i++, j++) {

					if ((*iter).service_comp[i].serviceID != srh->ServiceComp()[j].serviceID) {
						service_match = false;
						break;
					}
					if ((*iter).service_dest[i].addr != srh->ServiceDest()[j].addr) {
						dest_match = false;
						break;
					}
					sumDelay+=srh->ServiceComp()[j].delay;
					sumCost+=srh->ServiceComp()[j].cost;
				}
			}

		}

		if(route_match&&service_match&&dest_match){
			(*iter).sumCost=srh->sumCost();
			(*iter).sumDelay=srh->sumDelay();
			(*iter).qos=100-sumDelay-sumCost-0.1*hop_count;
			find=true;
			break;
		}
	}
	return find;
}

