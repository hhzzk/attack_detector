/*
 * MLTSTP_HW_DETECTOR.{cc,hh} -- element used to detect trojan detector 
 * HHZZK 
 *
 * Copyright (c) 2008 HHZZK.
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
#include "mltstp_hw_detector.hh"

CLICK_DECLS

MLTSTP_HW_DETECTOR::MLTSTP_HW_DETECTOR()
{
}

MLTSTP_HW_DETECTOR::~MLTSTP_HW_DETECTOR()
{
}


int
MLTSTP_HW_DETECTOR::initialize(ErrorHandler *errh)
{
    if(_record_head)
        return 0;

    _record_head = (mltstp_hw_records *)malloc(sizeof(mltstp_hw_records));
    if(!_record_head)
        retrun -1;

    _record_head->next = NULL;
    _record_head->conn_id = -1;

    return 0;
}

// Check if the ip is exists in the record
mltstp_hw_records* 
MLTSTP_HW_DETECTOR::check_record_exist(int32_t ip)
{
    mltstp_hw_records *tmp = _record_head;

    while(tmp)
    {
        if(tmp->ip == ip) 
        {
            //Check if the record is expired
            if((uint32_t)Timestamp::now().sec() - tmp->create_time > MLTSTP_HW_EXPIRATION)
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
MLTSTP_HW_DETECTOR::add_record(int32_t ip, int32_t time, int32_t steps)
{
    mltstp_hw_records* record = NULL;

    if(!_record_head)
        return false;

    record = (mltstp_hw_records *)malloc(sizeof(mltstp_hw_records));
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
MLTSTP_HW_DETECTOR::delete_record(mltstp_hw_records* record)
{
    mltstp_hw_records* pre_record = _record_head;
    mltstp_hw_records* tmp = _record_head;

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
MLTSTP_HW_DETECTOR::pull(int port)
{
    Packet *p = input(0).pull();
    if(p == NULL)
    {
        LOGE("Package is null");
        return NULL;
    }

    mltstp_hw_records* record = NULL;
    event_t *_event = extract_event(p);
    DNSDataModel model(_event->data);
    if(model.validate(_event->data + _event->event_len))
    {
        uint32_t ip = (uint32_t)_event->connect.dst_ip.s_addr;

        if(_event->event_type == HTTP_REQUEST)
        {
            record = check_record_exist(ip);         
            if(!record)
            {
                if(add_record(ip, (uint32_t)Timestamp::now().sec()), 2)
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
EXPORT_ELEMENT(MLTSTP_HW_DETECTOR)
ELEMENT_MT_SAFE(MLTSTP_HW_DETECTOR)
