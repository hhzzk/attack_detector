/*
 * DNSTUNNELS.{cc,hh} -- element used to detect trojan detector 
 * Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Meraki, Inc.
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

#include <click/config.h>
#include "dnstunnels.hh"
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>
#include <stdio.h>
CLICK_DECLS

DNSTUNNELS::SIDEJACKING()
{
}

DNSTUNNELS::~SIDEJACKING()
{
}


int
DNSTUNNELS::initialize(ErrorHandler *errh)
{
    if(_record_head)
        return 0;

    _record_head = (dnstunnels_record *)malloc(sizeof(dnstunnels_record));
    if(!_record_head)
        retrun -1;

    _record_head->next = NULL;
    _record_head->conn_id = -1;

    return 0;
}

// Check if the host ip is exists in the record
dnstunnels_record* 
DNSTUNNELS::check_hostip_exist(int host_ip)
{
    dnstunnels_record *tmp = _record_head;

    if(!tmp)
    {
        return NULL;
    }

    while(tmp)
    {
        if(tmp->host_ip == host_ip) 
            return tmp;
        tmp = tmp->next;
    }
    
    return NULL;
}

// Check if the record is exists
dnstunnels_record* 
DNSTUNNELS::check_record_exist(int awnser_ip)
{
    dnstunnels_record *tmp = _record_head;

    if(!tmp)
    {
        return NULL;
    }

    while(tmp)
    {
        if(tmp->anwser_ip == anwser_ip) 
            return tmp;
        tmp = tmp->next;
    }
    
    return NULL;
}

// Use head insert
bool
DNSTUNNELS::add_record(int ip, char* user_agent, char* cookie, int start, int expiration)
{
    dnstunnels_record* record = NULL;

    if(_record_head)
        return false;

    record = (dnstunnels_record *)malloc(sizeof(dnstunnels_record));
    if(record)
    {
        record->next = _record_head->next;
        _record_head->next = record;
        record->conn_id = conn_id;
        record->step = step;
        record->start_time = start;
        record->expiration_time = expiration;

        return true;
    }

    return false;
}

bool
DNSTUNNELS::delete_record(multisteps_record* record)
{
    dnstunnels_record* pre_record = _record_head;
    dnstunnels_record* tmp = _record_head;

    while(pre_record->next)
    {
        if(pre_record->next == record)
            break;
        
        pre_record = pre_record->next;
    }

    pre_record->next = record->next;
    free(record);
    record = NULL;

    return true;
}

void *
DNSTUNNELS::push(int, Packet *p_in)
{
    if(!p_in->has_network_header())
    {
        return;
    }

    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    int plength = p->length();
    dnstunnels_flow flow;
    printf("iph->ip_p is %d\n", iph->ip_p);   

    dnstunnels_record* record = NULL;

    if(event_type == EVENT_DNS_REPLY)
    {
        record = check_record_exist(anwser_ip)         
        if(!record)
        {
            add_record(host_ip, anwser_ip, Timestamp::now(), Timestamp::now() + EXPIRATION);
            return;
        }
        if(record->expiration_time < Timestamp::now())
        {
            delete_record(record);
            record = NULL;
            return;
        }

        record->count++;
        if(record->count > COUNT_THRESHOLD)
        {
            delete_record(record);
            alarm;
        }

    }
    else if(event_type == EVENT_IP_REQUEST)
    {
        record = check_hostip_exist(host_ip);         
        if(record)
        {
            delete_record(record); 
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(DNSTUNNELS)
ELEMENT_MT_SAFE(DNSTUNNELS)
