/*
 * MULTISTEPS.{cc,hh} -- element used to detect trojan detector 
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
#include "multisteps.hh"
#include <click/args.hh>
#include <click/packet_anno.hh>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <clicknet/ip.h>
#include <stdio.h>
CLICK_DECLS

MULTISTEPS::MULTISTEPS()
{
}

MULTISTEPS::~MULTISTEPS()
{
}


int
MULTISTEPS::initialize(ErrorHandler *errh)
{
    if(_record_head)
        return 0;

    _record_head = (multisteps_record *)malloc(sizeof(multisteps_record));
    if(!_record_head)
        retrun -1;

    _record_head->next = NULL;
    _record_head->conn_id = -1;

    return 0;
}

// Check if the connection is exists
multisteps_record* 
MULTISTEPS::check_conn_exist(int conn_id)
{
    multisteps_record *tmp = _record_head;

    if(!tmp)
    {
        return NULL;
    }

    while(tmp)
    {
        if(tmp->conn_id == conn_id) 
            return tmp;
        tmp = tmp->next;
    }
    
    return NULL;
}

// Use head insert
bool
MULTISTEPS::add_record(int conn_id, int step, int start, int expiration)
{
    multisteps_record* record = NULL;

    if(_record_head)
        return false;

    record = (multisteps_record *)malloc(sizeof(multisteps_record));
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
MULTISTEPS::delete_record(multisteps_record* record)
{
    multisteps_record* pre_record = _record_head;
    multisteps_record* tmp = _record_head;

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

Packet *
MULTISTEPS::simple_action(Packet *p_in)
{
    if(!p_in->has_network_header())
    {
        return p_in;
    }

    WritablePacket *p = p_in->uniqueify();
    click_ip *iph = p->ip_header();
    int plength = p->length();
    MULTISTEPS_flow flow;
    printf("iph->ip_p is %d\n", iph->ip_p);   

    multisteps_record* record = NULL;

    record = check_conn_exist(conn_id)         
    if(record->expiration_time < Timestamp::now())
    {
        delete_record(record);
        record = NULL;
    }

    if(protocol == PROTOCOL_SSH)
    {
        // If record exist, reset start time
        if(record)
        {
            record->start_time = Timestamp::now() 
        }
        else
        {
            add_record(conn_id, 1, Timestamp::now(), Timestamp::now() + 30sec)  
        }
    }
    else if(protocol == PROTOCOL_IRC)
    {
        if(record)
        {
            if(record->step == 4)
            {
                delete_record(record);
                printf("irc!!\n");
                printf("ATTACK!!\n");
            }
        }
    }
    else if(ftp request)
    {
        if(record)
        {
            if(record->step == 2 || record->step == 3)
            {
                record->step += 1; 
                printf("ftp request!!\n");
            }
        }
    }
    else if(http request)
    {
        if(record->step == 2)
        {
            record->step += 1;
            printf("http request!!\n");
            
        }
    }


}

CLICK_ENDDECLS
EXPORT_ELEMENT(MULTISTEPS)
ELEMENT_MT_SAFE(MULTISTEPS)
