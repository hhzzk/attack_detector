#ifndef CLICK_SIDEJACKING_HH
#define CLICK_SIDEJACKING_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct sidejacking_record
{
    int ip;
    char* user_agent;
    char* cookie;
    int start_time;
    int expiration_time;
    sidejacking_record* next;
}sidejacking_record; 


#define PROTOCOL_SSH 2222
#define PROTOCOL_IRC 6697
#define EXPIRATION 30

class SIDEJACKING : public Element {

    int _anno;
    sidejacking_record* _record_head = NULL;

  public:

    SIDEJACKING() CLICK_COLD;
    ~SIDEJACKING() CLICK_COLD;

    const char *class_name() const		{ return "SIDEJACKING"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int initialize(ErrorHandler *errh)
    sidejacking_record* check_record_exist(int);
    bool add_record(int, char*, char*);
    bool delete_record(sidejacking_record*);
    void push(int port, Packet*);
};

CLICK_ENDDECLS
#endif
