/*
 * requesttable.cc
 * Copyright (C) 2000 by the University of Southern California
 * $Id: requesttable.cc,v 1.4 2005/08/25 18:58:05 johnh Exp $
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 *
 *
 * The copyright of this module includes the following
 * linking-with-specific-other-licenses addition:
 *
 * In addition, as a special exception, the copyright holders of
 * this module give you permission to combine (via static or
 * dynamic linking) this module with free software programs or
 * libraries that are released under the GNU LGPL and with code
 * included in the standard release of ns-2 under the Apache 2.0
 * license or under otherwise-compatible licenses with advertising
 * requirements (or modified versions of such code, with unchanged
 * license).  You may copy and distribute such a system following the
 * terms of the GNU GPL for this module and the licenses of the
 * other code concerned, provided that you include the source code of
 * that other code when and as the GNU GPL requires distribution of
 * source code.
 *
 * Note that people who make modified versions of this module
 * are not obligated to grant this special exception for their
 * modified versions; it is their choice whether to do so.  The GNU
 * General Public License gives permission to release a modified
 * version without this exception; this exception also makes it
 * possible to release a modified version which carries forward this
 * exception.
 *
 */
//
// Other copyrights might apply to parts of this software and are so
// noted when applicable.
//
// Ported from CMU/Monarch's code, appropriate copyright applies.  
/* requesttable.h

 implement a table to keep track of the most current request
 number we've heard from a node in terms of that node's id

 */

#include "scpath.h"
#include "constants.h"
#include "requesttable.h"
#include "hdr_scdsr.h"

SCRequestTable::SCRequestTable(int s) {
	table = new Entry[size];
	this->size = s;
	ptr = 0;
}

SCRequestTable::~SCRequestTable() {
	delete[] table;
}

int SCRequestTable::find(const SCID& net_id, const SCID& MAC_id) const {
	for (int c = 0; c < size; c++)
		if (table[c].net_id == net_id || table[c].MAC_id == MAC_id)
			return c;
	return size;
}

int SCRequestTable::get(const SCID& id) const {
	int existing_entry = find(id, id);

	if (existing_entry >= size) {
		return 0;
	}
	return table[existing_entry].req_num;
}

Entry*
SCRequestTable::getEntry(const SCID& id) {
	int existing_entry = find(id, id);

	if (existing_entry >= size) {
		table[ptr].MAC_id = ::sc_invalid_addr;
		table[ptr].net_id = id;
		table[ptr].req_num = 0;
		table[ptr].last_arp = 0.0;
		table[ptr].rt_reqs_outstanding = 0;
		table[ptr].last_rt_req = -(sc_rt_rq_period + 1.0);
		existing_entry = ptr;
		ptr = (ptr + 1) % size;
	}
	return &(table[existing_entry]);
}

void SCRequestTable::insert(const SCID& net_id, int req_num) {
	insert(net_id, ::sc_invalid_addr, req_num);
}

void SCRequestTable::insert(const SCID& net_id, const SCID& MAC_id,
		int req_num) {
	int existing_entry = find(net_id, MAC_id);

	if (existing_entry < size) {
		if (table[existing_entry].MAC_id == ::sc_invalid_addr)
			table[existing_entry].MAC_id = MAC_id; // handle creations by getEntry
		table[existing_entry].req_num = req_num;
		return;
	}

	// otherwise add it in
	table[ptr].MAC_id = MAC_id;
	table[ptr].net_id = net_id;
	table[ptr].req_num = req_num;
	table[ptr].last_arp = 0.0;
	table[ptr].rt_reqs_outstanding = 0;
	table[ptr].last_rt_req = -(sc_rt_rq_period + 1.0);
	ptr = (ptr + 1) % size;
}

ServiceRequestTable::ServiceRequestTable(int size) {
	table = new SReqEntry[size];
	this->size = size;
	ptr = 0;

}

ServiceRequestTable::~ServiceRequestTable() {
	delete[] table;
}

int ServiceRequestTable::find(struct hdr_scdsr *srh) {
	for (int c = 0; c < size; c++)
		if (table[c].sreq_id == srh->sreqID()
				&& table[c].source_node == srh->sreqSourceNode()
				&& table[c].service_index == srh->ServiceIndex())
			return c;
	return size;
}

//Insert or update service request into service request table
//return if we should forward the service request or discard it.
void ServiceRequestTable::insert(struct hdr_scdsr *srh) {

	int existing_entry = find(srh);

	//if we haven't find the same request, then insert into table
	if (existing_entry >= size) {
		table[ptr].sreq_id = srh->sreqID();
		table[ptr].source_node = srh->sreqSourceNode();
		table[ptr].service_index = srh->ServiceIndex();
		table[ptr].hop_count = srh->sreqHopCount();
		table[ptr].sum_delay = srh->sumDelay();
		table[ptr].sum_cost = srh->sumCost();
		ptr = (ptr + 1) % size;

	}
	//if the same request exists, see if it needs to be updated
	else {
		int result=compare(table[existing_entry],srh);
		if (result == 1) {
			table[existing_entry].hop_count = srh->sreqHopCount();
			table[existing_entry].sum_delay =srh->sumDelay();
			table[existing_entry].sum_cost = srh->sumCost();
		}
	}
	return;

}

bool ServiceRequestTable::ifDiscard(struct hdr_scdsr *srh) {
	int existing_entry = find(srh);
	if (existing_entry >= size)
		return false;
	else {
		int compareResult = compare(table[existing_entry],srh);
		if (compareResult < 0)
			return true;
		else if (compareResult == 0)
			return true;
		else {
			table[existing_entry].hop_count = srh->sreqHopCount();
			table[existing_entry].sum_delay =srh->sumDelay();
			table[existing_entry].sum_cost = srh->sumCost();
			return false;
		}
	}

}

int ServiceRequestTable::compare(SReqEntry entry,
		struct hdr_scdsr *srh) {
	if (srh->sumDelay() < entry.sum_delay
			&& srh->sumCost() < entry.sum_cost)
		return 1; //it's a better request, we should update
	if(srh->sumDelay()+srh->sumCost()<entry.sum_delay+entry.sum_cost)
		return 1;
	else if (srh->sumDelay() > entry.sum_delay
			&& srh->sumCost() > entry.sum_cost)
		return -1; //it's a worse request, we ignore it
	else
		return 0;  //we can't tell which is better
}
