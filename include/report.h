#ifndef RECON_REPORT_H
#define RECON_REPORT_H

/* Opens/closes the optional report output file (sets g_outfile). */
int  report_open(const char *path);
void report_close(void);

#endif /* RECON_REPORT_H */
