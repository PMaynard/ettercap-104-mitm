#ifndef EC_RESOLV_H
#define EC_RESOLV_H

#include <ec_inet.h>

#include <arpa/nameser.h>
#include <resolv.h>

/*
 * glibc 2.1.x does not have new NG_GET* macros...
 * implement the hack here.
 */

#ifndef HAVE_NS_GET
   /* functions */
   #define NS_GET16 GETSHORT
   #define NS_GET32 GETLONG
   #define NS_PUT16 PUTSHORT
   #define NS_PUT32 PUTLONG
   /* constants */
   #define NS_MAXDNAME MAXDNAME
   #define ns_c_in C_IN
   #define ns_r_noerror NOERROR
   #define ns_t_cname T_CNAME
   #define ns_t_ptr T_PTR
   #define ns_t_a T_A
#endif



#define MAX_HOSTNAME_LEN   64

extern int host_iptoa(struct ip_addr *ip, char *name);

/* used by ec_dns to insert passively sniffed dns answers */
extern void resolv_cache_insert(struct ip_addr *ip, char *name);
   

   
#endif

/* EOF */

// vim:ts=3:expandtab

