
/*
 * path.h
 * Copyright (C) 2000 by the University of Southern California
 * $Id: path.h,v 1.7 2005/08/25 18:58:05 johnh Exp $
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

// Other copyrights might apply to parts of this software and are so
// noted when applicable.
//
// Ported from CMU/Monarch's code, appropriate copyright applies.  
/* -*- c++ -*-
   path.h

   handles source routes
   
*/
#ifndef _scpath_h
#define _scpath_h

extern "C" {
#include <stdio.h>
#include <assert.h>

}
#include <iostream>
#include <packet.h>

#define MAX_SR_LEN 16		// longest source route we can handle

class SCPath;			// forward declaration

// state used for tracing the performance of the caches
enum SCLink_Type {SCLT_NONE = 0, SCLT_TESTED = 1, SCLT_UNTESTED = 2};
enum SCLog_Status {SCLS_NONE = 0, SCLS_UNLOGGED = 1, SCLS_LOGGED = 2};
// some type conversion between exisiting NS code and old DSR sim
typedef double Time;
enum SCID_Type {SCNONE = NS_AF_NONE, SCMAC = NS_AF_ILINK, SCIP = NS_AF_INET };

struct scdsr_addr {
	int addr_type; /* same as hdr_cmn in packet.h */
	nsaddr_t addr;
	/*
	 * Metrics that I want to collect at each node
	 */
	//double Pt_;
};

struct SCID {
  friend class SCPath; 
  SCID() :addr(0),
			type(SCNONE), t(-1), link_type(SCLT_NONE), log_stat(SCLS_NONE) {
	}
	//  SCID():addr(0),type(NONE) {}	// remove for speed? -dam 1/23/98
	//SCID(unsigned long name, ID_Type t):addr(name),type(t), t(-1), link_type(LT_NONE),log_stat(LS_NONE)
	//{
	//assert(type == NONE || type == MAC || type == IP);
	//}
  SCID(unsigned long name, SCID_Type t) :
			addr(name), type(t), t(-1), link_type(SCLT_NONE), log_stat(SCLS_NONE)
					{
		assert(type == NONE || type == MAC || type == IP);
	}
  inline SCID(const struct scdsr_addr &a): addr(a.addr),
    type((enum SCID_Type) a.addr_type), t(-1), link_type(SCLT_NONE),
	  log_stat(SCLS_NONE)
	{
		assert(type == NONE || type == MAC || type == IP);
	}
  inline void fillSRAddr(struct scdsr_addr& a) {
	  a.addr_type = (int) type;
	  a.addr = addr;
  }    
  inline nsaddr_t getNSAddr_t() const {
	  assert(type == IP); return addr;
  }
  inline bool operator == (const SCID& id2) const {
	  return (type == id2.type) && (addr == id2.addr);
  }
  inline bool operator != (const SCID& id2) const {return !operator==(id2);}
  inline int size() const {return (type == SCIP ? 4 : 6);}
  void unparse(FILE* out) const;
  char* dump() const;

  unsigned long addr;
  SCID_Type type;
  Time t;			// when was this SCID added to the route
  SCLink_Type link_type;
  SCLog_Status log_stat;

};

extern SCID sc_invalid_addr;
extern SCID SC_IP_broadcast;


class SCPath {
friend void compressPath(SCPath& path);
friend void CopyIntoPath(SCPath& to, const SCPath& from, int start, int stop);
public:
  SCPath();
  SCPath(int route_len, const SCID *route = NULL);
  SCPath(const SCPath& old);
  SCPath(const struct scdsr_addr *addrs, int len);
  SCPath(struct hdr_scdsr *srh);

  ~SCPath();

  void fillSR(struct hdr_scdsr *srh);
  SCID* Path(){return this->path;}
  inline SCID& next() {assert(cur_index < len); return path[cur_index++];}

  inline void resetIterator() {  cur_index = 0;}
  inline void reset() {len = 0; cur_index = 0;}

  inline void setIterator(int i) {assert(i>=0 && i<len); cur_index = i;}
  inline void setLength(int l) {assert(l>=0 && l<=MAX_SR_LEN); len = l;}
  inline SCID& operator[] (int n) const {  
    assert(n < len && n >= 0);
    return path[n];}
  void operator=(const SCPath& rhs);
  bool operator==(const SCPath& rhs);
  inline void appendToPath(const SCID& id) { 
    assert(len < MAX_SR_LEN);
    path[len++] = id;
  }


  void appendPath(SCPath& p);
  bool member(const SCID& id) const;
  bool member(const SCID& net_id, const SCID& MAC_id) const;
  SCPath copy() const;
  void copyInto(SCPath& to) const;
  SCPath reverse() const;
  void reverseInPlace();
  void removeSection(int from, int to);
  // the elements at indices from -> to-1 are removed from the path

  inline bool full() const {return (len >= MAX_SR_LEN);}
  inline int length() const {return len;}
  inline int& length()  {return len;}
  inline int index() const {return cur_index;}
  inline int& index() {return cur_index;}

  int size() const; // # of bytes needed to hold path in packet
  void unparse(FILE *out) const;
  char *dump() const;
  //inline SCID &owner() {return path_owner;}

  void checkpath(void) const;
private:
  int len;
  int cur_index;
  SCID* path;//delete
  //SCID path_owner;//delete
  //SCID* service_path;

};




void compressPath(SCPath& path);
// take a path and remove any double backs from it
// eg:  A B C B D --> A B D

void CopyIntoPath(SCPath& to, const SCPath& from, int start, int stop);
// sets to[0->(stop-start)] = from[start->stop]

#endif // _path_h
