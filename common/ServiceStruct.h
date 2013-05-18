/*
 * ServiceStruct.h
 *
 *  Created on: Apr 28, 2013
 *      Author: kenchy
 */

#ifndef SERVICESTRUCT_H_
#define SERVICESTRUCT_H_

#define Service_Table_Size 20
#define MAX_SERVICE_COMP_SZ 10

typedef int sctype;

struct Service {
	sctype serviceID;
	char function[6];
	float delay;
	float cost;
	//and others
	Service(){
		serviceID=-1;
		delay=0;
		cost=0;
	}
};


#endif /* SERVICESTRUCT_H_ */
