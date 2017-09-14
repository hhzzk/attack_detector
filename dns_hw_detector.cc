/*
 * DNSTUNNELS.{cc,hh} -- element used to detect dns tunnels attack 
 * HHZZK 
 *
 * Copyright (c) 2017 HHZZK
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <stdio.h>
//#include <click/args.hh>
#include <clicknet/ip.h>
#include <click/logger.h>
#include <click/config.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/dns.h>
#include <click/timer.hh>
#include <click/packet_anno.hh>

#include "event.hh"
#include "datamodel.hh"
#include "dnstunnels.hh"
#include "dnsanalyzer.hh"

CLICK_DECLS

DNSTUNNELS::DNSTUNNELS()
{
}

DNSTUNNELS::~DNSTUNNELS()
{
}

int
DNSTUNNELS::configure(Vector<String> &conf, ErrorHandler *errh)
{
    return 0;
}

Packet *
DNSTUNNELS::pull(int port)
{
    Packet *p = input(0).pull();
    if(p == NULL)
    {
        LOGE("Package is null");
        return NULL;
    }

    dnstunnels_record *record = NULL;
    event_t *_event = extract_event(p);
    DNSDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        uint32_t ip = get_value<DNSDataModel, DNS_FIELD_RECORD_IP>(model);
        char *qname = get_field<DNSDataModel, DNS_FIELD_QNAME>(model);

        int query_len = strlen(qname);
        int i = 0;
        int num_count = 0;
        LOGE("query len is %d", query_len);
        if(query_len > QUERY_LEN_THRESHOLD)
        {
            for(i=0; i<query_len; i++)
            {
                if(qname[i] > '0' && qname[i] < '9')
                    num_count++;
            }
        }

        if(num_count*10/query_len > PERCENTAGE_OF_COUNT)
        {
            LOGE("Suspicious! Numberical charicter overload");
            return p;
        }
    }
    else
    {
        LOGE("DataModel invalid!");
    }
    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNSTUNNELS)
ELEMENT_MT_SAFE(DNSTUNNELS)
