#!/bin/bash
g++ -DSTANDALONE_UPNP -I../../include -I./ echo_server.cc upnp.cc -Wall -lminiupnpc -o upnp
