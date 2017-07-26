/*
 * SIDEJACKING.{cc,hh} -- element used to detect trojan detector 
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
#include <clicknet/ip.h>
#include <click/config.h>
#include <clicknet/tcp.h>
#include <clicknet/udp.h>
#include <click/logger.h>
#include <click/packet_anno.hh>

#include "event.hh"
#include "datamodel.hh"
#include "sidejacking.hh"
#include "httpanalyzer.hh"

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

    _record_head = (sidejacking_record *)malloc(sizeof(sidejacking_record));
    if(!_record_head)
        return -1;

    _record_head->next = NULL;

    return 0;
}

// Check if the record is exists (cookie as index)
sidejacking_record* 
SIDEJACKING::check_cookie_exist(char* cookie)
{
    sidejacking_record *tmp = _record_head;

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
SIDEJACKING::add_record(char *cookie, int ip, char* user_agent)
{
    sidejacking_record* record = NULL;

    if(_record_head)
        return false;

    record = (sidejacking_record *)malloc(sizeof(sidejacking_record));
    if(record)
    {
        record->next = _record_head->next;
        _record_head->next = record;
        record->cookie = (char *) malloc(strlen(cookie));
        strcpy(cookie, record->cookie);
        record->user_agent = (char *) malloc(strlen(user_agent));
        strcpy(user_agent, record->user_agent);
        record->ip = ip;

        return true;
    }

    return false;
}

Packet *
SIDEJACKING::pull(int port)
{
    Packet *p = input(0).pull();
    if(p == NULL)
    {
        LOGE("Package is null");
        return NULL;
    }

    sidejacking_record* record = NULL;
    event_t *_event = extract_event(p);
    HttpDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        char* cookie = get_field<HttpDataModel, HTTP_FIELD_COOKIE>(model);
        LOGE("Sidejacking: model get cookie: %s", cookie);
        char* user_agent = get_field<HttpDataModel, HTTP_FIELD_USRAGENT>(model);
        LOGE("Sidejacking: model get useragent: %s", user_agent);

        uint32_t ip = (uint32_t)_event->connect.src_ip.s_addr;

        record = check_cookie_exist(cookie); 
        if(!record)
        {
            if(add_record(cookie, ip, user_agent))
            {
                LOGE("Adding new record success, cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            }
            else
            {
                LOGE("Adding new record failed, cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            }
            return p;
        }

        if(ip == record->ip)
        {
            if(user_agent == record->user_agent)        
            {
                LOGE("Record : cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            }
            else
            {
                record->user_agent = user_agent;
                LOGE("Session cookie reuse: cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);

            }
        }
        else
        {
            if(user_agent == record->user_agent)
            {
                if(DHCP_CONTEXT_AVALIABLE)
                {
                
                }
                else
                {
                    return p;
                }
            }
            else
            {
                LOGE("Alarm sidejacking!!!: cookie = %s, ip = %u, user agent = %s", cookie, ip, user_agent);
            }
        }

        free(cookie);
        free(user_agent);
    }
    else
    {
        LOGE("Sidejacking: the DataModel is invalid for the data, field len %u", model.len());
    }

    dealloc_event(_event);

    return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SIDEJACKING)
ELEMENT_MT_SAFE(SIDEJACKING)
