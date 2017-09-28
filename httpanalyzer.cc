#include <click/config.h>
#include <click/logger.h>
#include <clicknet/tcp.h>
#include <clicknet/http.h>
#include "packet_tags.hh"
extern "C" {
#include <string.h>
}

#include "httpanalyzer.hh"
#include "event.hh"
#include "datamodel.hh"

CLICK_DECLS

void HTTPAnalyzer::push(int port, Packet* p)
{
    /*
    if(!get_tag(p, PTAG_MLTSTP))
    {
        p->kill();
        return;
    }
    */
    const unsigned char* payload = (const unsigned char*)p->transport_header() + (p->tcp_header()->th_off << 2);
    HttpHeaders headers;
    if(0 == http_parse(payload, p->end_data(), &headers) && headers.size() > 0)
    {
        String cookie = headers.find("Cookie");
        String content_type = headers.find("Content-Type");
        if (content_type)
        {
            LOGE("Content-Type: %s", content_type.c_str());
            if(strncmp(content_type.c_str(), "text/html", 9) == 0)
            {
                event_t * event = alloc_event_data(0);
                event->event_type = HTTP_RESPONSE_HTML;
                event->fill_connect(p);
                send_event(event);
                dealloc_event(event);
                p->kill();
            }
            else if(strncmp(content_type.c_str(), "application/octet-stream", 24) == 0)
            {
                event_t * event = alloc_event_data(0);
                event->event_type = HTTP_RESPONSE_EXE;
                event->fill_connect(p);
                send_event(event);
                dealloc_event(event);
                p->kill();
            }
            else if(strncmp(content_type.c_str(), "application/zip", 15) == 0)
            {
                event_t * event = alloc_event_data(0);
                event->event_type = HTTP_RESPONSE_ZIP;
                event->fill_connect(p);
                send_event(event);
                dealloc_event(event);
                p->kill();
            }
        }
        if(cookie)
        {
            String useragent = headers.find("User-Agent");
            // If no useragent found in headers, fill in random integer
            if(!useragent)
                useragent = String(click_random());
            event_t * event = alloc_event_data(2, cookie.length(), useragent.length());
            event->event_type = HTTP_COOKIE_USERAGENT;
            event->fill_connect(p);
            event->get_writer()(cookie.length(), cookie.c_str())
                (useragent.length(), useragent.c_str());
            LOG_DEBUG("save cookie: %s", cookie.c_str());
            LOG_DEBUG("save useragent: %s", useragent.c_str());
            send_event(event);
            dealloc_event(event);
        }
    }
    p->kill();
}

CLICK_ENDDECLS
EXPORT_ELEMENT(HTTPAnalyzer)
