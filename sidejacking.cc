/*
 * SIDEJACKING.{cc,hh} -- element used to detect trojan detector 
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
#include "sidejacking.hh"
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>
#include <stdio.h>
CLICK_DECLS

SIDEJACKING::SIDEJACKING()
{
}

SIDEJACKING::~SIDEJACKING()
{
}


int
SIDEJACKING::initialize(ErrorHandler *errh)
{
    if(_record_head)
        return 0;

    _record_head = (sidejacking_record *)malloc(sizeof(multisteps_record));
    if(!_record_head)
        retrun -1;

    _record_head->next = NULL;
    _record_head->conn_id = -1;

    return 0;
}

// Check if the record is exists
sidejacking_record* 
SIDEJACKING::check_record_exist(char* cookie)
{
    sidejacking_record *tmp = _record_head;

    if(!tmp)
    {
        return NULL;
    }

    while(tmp)
    {
        if(strcmp(tmp->cookie, cookie) == 0) 
            return tmp;
        tmp = tmp->next;
    }
    
    return NULL;
}

// Use head insert
bool
SIDEJACKING::add_record(int ip, char* user_agent, char* cookie)
{
    sidejacking_record* record = NULL;

    if(_record_head)
        return false;

    record = (sidejacking_record *)malloc(sizeof(multisteps_record));
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
SIDEJACKING::delete_record(multisteps_record* record)
{
    sidejacking_record* pre_record = _record_head;
    sidejacking_record* tmp = _record_head;

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
SIDEJACKING::push(int, Packet *p_in)
{
    if(!p_in->has_network_header())
    {
        return p_in;
    }

    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    int plength = p->length();
    SIDEJACKING_flow flow;
    printf("iph->ip_p is %d\n", iph->ip_p);   

    sidejacking_record* record = NULL;

    record = check_record_exist(cookie)         
    if(!record)
    {
        add_record(ip, user_agent, cookie);
        return;
    }
    if(record->expiration_time < Timestamp::now())
    {
        delete_record(record);
        record = NULL;
    }

    if(ip == record->ip)
    {
        if(user_agent == record->user_agent)        
        {
             update cookie 
        }
        else
        {
            delete_record(record);
            report session cookie reuse; 

        }
    }
    else
    {
        if(user_agent == record->user_agent)
        {
        }
        else
        {
            alarm sidejacking; 
        }
    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SIDEJACKING)
ELEMENT_MT_SAFE(SIDEJACKING)
