#ifndef CLICK_MULTISTEPS_HH
#define CLICK_MULTISTEPS_HH
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

typedef struct multisteps_record
{
    int32_t ip;
    int32_t steps;
    int32_t create_time;
    multisteps_record* next;
}multisteps_record; 

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
    multisteps_record* check_record_exist(int32_t);
    bool add_record(int32_t, int32_t, int32_t);
    bool delete_record(multisteps_record*);
    void *pull(int);

};

CLICK_ENDDECLS
#endif
