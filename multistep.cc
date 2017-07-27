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

#include <stdio.h>
#include <clicknet/ip.h>
#include <click/config.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/packet_anno.hh>

#include "event.hh"
#include "datamodel.hh"
#include "multisteps.hh"

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

// Check if the ip is exists in the record
multisteps_record* 
MULTISTEPS::check_record_exist(int32_t ip)
{
    multisteps_record *tmp = _record_head;

    while(tmp)
    {
        if(tmp->ip == ip) 
        {
            //Check if the record is expired
            if((uint32_t)Timestamp::now().sec() - tmp->create_time > EXPIRATION)
            {
                delete_record(tmp); 
                return NULL;
            }
            else 
                return tmp;
        }
        tmp = tmp->next;
    }
    
    return NULL;
}

// Use head insert
bool
MULTISTEPS::add_record(int32_t ip, int32_t time, int32_t steps)
{
    multisteps_record* record = NULL;

    if(!_record_head)
        return false;

    record = (multisteps_record *)malloc(sizeof(multisteps_record));
    if(record)
    {
        record->next = _record_head->next;
        _record_head->next = record;
        record->ip= ip;
        record->steps = steps;
        record->create_time = time;

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

void
MULTISTEPS::pull(int port)
{
    Packet *p = input(0).pull();
    if(p == NULL)
    {
        LOGE("Package is null");
        return NULL;
    }

    multisteps_record* record = NULL;
    event_t *_event = extract_event(p);
    DNSDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        uint32_t ip = (uint32_t)_event->connect.dst_ip.s_addr;

        if(_event->event_type == SSH_AUTH_ATTEMPED)
        {
            record = check_record_exist(ip);         
            if(!record)
            {
                if(add_record(ip, (uint32_t)Timestamp::now().sec()), 1)
                {
                    LOGE("Adding new record success, ip = %u", ip);
                }
                else
                {
                    LOGE("Adding new record failure, ip = %u", ip);
                }
                return p;
            }
        }
        else if(_event->event_type == HTTP_REQUEST) 
        {
            record = check_record_exist(ip);         
            if(record)
            {
                if(record->steps == 1)
                {
                    record->steps = 2;
                }
            }
        }
        else if(_event->event_type == FTP_REQUEST ||
                _event->event_type == FTP_DATA_ACTIVITY)
        {
            record = check_record_exist(ip);         
            if(record)
            {
                if(record->steps == 2)
                    record->steps = 3;
                else if(record->steps == 3)
                    LOGE("Mutistep Attack!!");
            }
            return p;
        }
        else
        {
            LOGE("Error event type");
        }

    }
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MULTISTEPS)
ELEMENT_MT_SAFE(MULTISTEPS)
