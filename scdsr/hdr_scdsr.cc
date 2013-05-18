// Ported from CMU/Monarch's code, appropriate copyright applies.  
/* -*- c++ -*-
   hdr_sr.cc
   source route header
*/

#include <stdio.h>
#include "hdr_scdsr.h"

int hdr_scdsr::offset_;

static class SCDSRHeaderClass : public PacketHeaderClass {
public:
	SCDSRHeaderClass() : PacketHeaderClass("PacketHeader/SCDSR",
					     sizeof(hdr_scdsr)) {
		offset(&hdr_scdsr::offset_);

#ifdef DSCDSR_CONST_HDR_SZ
		fprintf(stderr,"WARNING: DSCDSR treating all source route headers\n"
			"as having length %d. this should be used only to estimate effect\n"
			"of no longer needing a scdsrc rt in each packet\n",SCDSR_HDR_SZ);
#endif

	}
#if 0
	void export_offsets() {
		field_offset("valid_", OFFSET(hdr_scdsr, valid_));
		field_offset("num_addrs_", OFFSET(hdr_scdsr, num_addrs_));
		field_offset("cur_addr_", OFFSET(hdr_scdsr, cur_addr_));
	}
#endif
} class_SCDSRhdr;

char *
hdr_scdsr::dump()
{
  static char buf[100];
  dump(buf);
  return (buf);
}

void
hdr_scdsr::dump(char *buf)
{
  char *ptr = buf;
  *ptr++ = '[';
  for (int i = 0; i < num_addrs_; i++)
    {
      ptr += sprintf(ptr, "%s%d ",
		     (i == cur_addr_) ? "|" : "",
		     addrs()[i].addr);
    }
  *ptr++ = ']';
  *ptr = '\0';
}
