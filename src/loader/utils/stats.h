#pragma once

#include <xdp/libxdp.h>

#include <common/all.h>

#include <loader/utils/config.h>
#include <loader/utils/helpers.h>

#include <time.h>
#include <sqlite3.h>

int calc_stats(int map_stats, int cpus, int per_second);
int save_stats_db(sqlite3* db, int map_stats, int cpus);