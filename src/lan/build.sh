#!/bin/bash
g++ -I./ echo_server.cc upnp.cc -Wall -lminiupnpc -o upnp
