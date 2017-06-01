#ifndef CLICK_DNSTUNNELS_HH
#define CLICK_DNSTUNNELS_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct dnstunnels_record
{
    int host_ip;
    int anwser_ip;
    int count;
    int start_time;
    int expiration_time;
    dnstunnels_record* next;
}dnstunnels_record; 

#define PROTOCOL_SSH 2222
#define PROTOCOL_IRC 6697
#define EXPIRATION 30

class DNSTUNNELS : public Element {

    int _anno;
    dnstunnels_record* _record_head = NULL;

  public:

    DNSTUNNELS() CLICK_COLD;
    ~DNSTUNNELS() CLICK_COLD;

    const char *class_name() const		{ return "DNSTUNNELS"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int initialize(ErrorHandler *errh)
    dnstunnels_record* check_conn_exist(int);
    bool add_record(int, int, int, int);
    bool delete_record(dnstunnels_record*);
    void push(int port, Packet*);
};

CLICK_ENDDECLS
#endif
