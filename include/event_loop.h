#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include "config.h"
#include "socket_binding.h"
#include "zonefile_parser.h"

int event_loop(listeners *list, config_type *config, zones *zn);

#endif