#ifndef CLICK_MULTISTEPS_HH
#define CLICK_MULTISTEPS_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct multisteps_record
{
    int conn_id;
    int step;
    int start_time;
    int expiration_time;
    multisteps_record* next;
}multisteps_record; 


#define PROTOCOL_SSH 2222
#define PROTOCOL_IRC 6697
#define EXPIRATION 30

class MULTISTEPS : public Element {

    int _anno;
    multisteps_record* _record_head = NULL;

  public:

    MULTISTEPS() CLICK_COLD;
    ~MULTISTEPS() CLICK_COLD;

    const char *class_name() const		{ return "MULTISTEPS"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int initialize(ErrorHandler *errh)
    multisteps_record* check_conn_exist(int);
    bool add_record(int, int, int, int);
    bool delete_record(multisteps_record*);
    void *push(int, Packet *);

};

CLICK_ENDDECLS
#endif
