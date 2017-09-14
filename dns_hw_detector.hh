#ifndef CLICK_DNSTUNNELS_HH
#define CLICK_DNSTUNNELS_HH

#include <click/timer.hh>
#include <click/element.hh>
#include <click/ipaddress.hh>
CLICK_DECLS

#define PERCENTAGE_OF_COUNT 2
#define QUERY_LEN_THRESHOLD 52

class DNSTUNNELS : public Element {

    int _anno;

  public:

    DNSTUNNELS() CLICK_COLD;
    ~DNSTUNNELS() CLICK_COLD;

    const char *class_name() const		{ return "DNSTUNNELS"; }
    const char *port_count() const		{ return PORTS_1_1; }

    bool can_live_reconfigure() const		{ return true; }

    int configure(Vector<String> &conf, ErrorHandler *errh);
    Packet *pull(int port);

};

CLICK_ENDDECLS
#endif
