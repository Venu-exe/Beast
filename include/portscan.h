#ifndef RECON_PORTSCAN_H
#define RECON_PORTSCAN_H

/* Curated list of commonly-open ports, used when the user passes -p top. */
extern int top_ports[];
extern int top_ports_count;

/* Parses a port spec ("top", "1-1000", or "22,80,443") into a freshly
 * malloc'd array written to *out_list. Returns the number of ports, or
 * <= 0 on failure (in which case *out_list may be unset). Caller frees. */
int parse_ports(const char *spec, int **out_list);

/* Runs a multi-threaded TCP connect scan against g_target_ip over the
 * ports in portlist/portcount, using `threads` worker threads, and
 * prints/JSON-records results. On return, *open_ports_out is a freshly
 * malloc'd array (caller frees) of the ports found open, and
 * *open_count_out is its length. Either out pointer may be NULL if the
 * caller doesn't need the open-port list. */
void run_port_scan(int *portlist, int portcount, int threads,
                    int **open_ports_out, int *open_count_out);

#endif /* RECON_PORTSCAN_H */
