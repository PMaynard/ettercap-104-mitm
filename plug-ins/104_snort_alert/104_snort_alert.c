/*
    104 Snort Alerts -- Triggers a few snort rules.
    
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */

#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_send.h>
#include <ec_session_tcp.h>

#include <stdlib.h>
#include <string.h>

#include <stdio.h>

/* Comment out if you want to use one octet for the Common address of ASDU */
#define ADDR_TWO_OCTECTS 0;

enum {I_FORMAT, S_FORMAT, U_FORMAT};
enum {INVALID_START, SPON_COT, INVALID_COT, INVALID_COT_45, INVALID_COT_01, INVALID_COT_15, INVALID_COT_32, TYPE_ID_RESET, BROADCAST_ADDRESS, INVALID_LENGTH, TYPE_ID_INVALID_CONTROL_DIR, TYPE_ID_INVALID_MONITOR_DIR};

u_char START        = 0x68;
u_char RESET        = 0x69;
u_char M_ME_TF_1    = 0x24;
u_char M_SP_TB_1    = 0x1e;
#ifdef ADDR_TWO_OCTECTS
  short BROADCAST    = 0xFFFF;
#else 
  u_char BROADCAST   = 0xFF;
#endif

struct apci_header {
  u_char start;
  u_int8 length;
  u_int8 control_1;
  u_int8 control_2;
  u_int8 control_3;
  u_int8 control_4;
};

struct asdu_header {
  u_char type_id;
  // Structure Qualifier
  u_char num_objects : 7;
  u_char sq : 1;
  // Cause of transmission 
  u_char COT: 6;
  u_char PN : 1;
  u_char T : 1;
  #ifdef ADDR_TWO_OCTECTS
    short originator_addr;
  #else 
    u_char originator_addr;
  #endif
  u_int IOA : 16; //8, 16 or 24
  u_char spacer;
  // Specifically for a SIQ information element
  u_char spi : 1;
  u_char blank : 3;
  u_char bl : 1;
  u_char sb : 1;
  u_char nt : 1;
  u_char iv : 1;
};

static const char *triggers[] = {
"0 INVALID_START", "1 SPON_COT", "2 INVALID_COT", "3 INVALID_COT_45", "4 INVALID_COT_01", "5 INVALID_COT_15", "6 INVALID_COT_32", "7 TYPE_ID_RESET", "8 BROADCAST_ADDRESS", "9 INVALID_LENGTH", "10 TYPE_ID_INVALID_CONTROL_DIR", "11 TYPE_ID_INVALID_MONITOR_DIR"
};

int trigger = 0;

/* prototypes is required for -Wmissing-prototypes */

/* 
 * this function must be present.
 * it is the entry point of the plugin 
 */
int plugin_load(void *);

/* additional functions */
static int spoof_104_init(void *); 
static int spoof_104_fini(void *);

static void parse_tcp(struct packet_object *po);
static int get_type(u_int8 control);
static void print_apci(struct apci_header *apci);
static void print_asdu(struct asdu_header *asdu);


/* plugin operations */

struct plugin_ops spoof_104_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "alert_snort_104",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Triggers SNORT rules for IEC 104.",  
   /* the plugin version. */ 
   .version =           "0.0",   
   /* activation function */
   .init =              &spoof_104_init,
   /* deactivation function */                     
   .fini =              &spoof_104_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   DEBUG_MSG("Spoof 104 plugin load function.");
   /*
    *  in this fuction we MUST call the registration procedure that will set
    *  up the plugin according to the plugin_ops structure.
    *  the returned value MUST be the same as plugin_register()
    *  the opaque pointer params MUST be passed to plugin_register()
    */
   return plugin_register(handle, &spoof_104_ops);
}

/*********************************************************/

static int spoof_104_init(void *dummy) 
{
   /* the control is given to this function
    * and ettercap is suspended until its return.
    * 
    * you can create a thread and return immediately
    * and then kill it in the fini function.
    *
    * you can also set an hook point with
    * hook_add(), in this case you have to set the
    * plugin type to PL_HOOK.
    */
   
   USER_MSG("Spoof 104: Plugin running...\n");

   hook_add(HOOK_PACKET_TCP, &parse_tcp);

   /* return PLUGIN_FINISHED if the plugin has terminated
    * its execution.
    * return PLUGIN_RUNNING if it has spawned a thread or it
    * is hooked to an ettercap hookpoint and
    * it needs to be deactivated with the fini method.
    */
   return PLUGIN_RUNNING;
}


static int spoof_104_fini(void *dummy) 
{
   /* 
    * called to terminate a plugin.
    * usually to kill threads created in the 
    * init function or to remove hook added 
    * previously.
    */
   USER_MSG("Spoof 104: Plugin finalization.\n");

   hook_del(HOOK_PACKET_TCP, &parse_tcp); 

   return PLUGIN_FINISHED;
}

static void parse_tcp(struct packet_object *po)
{

  /* don't show packets while operating */
  GBL_OPTIONS->quiet = 1;

  struct apci_header *apci;
  struct asdu_header *asdu;
  apci = (struct apci_header *)po->DATA.data;
  asdu = (struct asdu_header *)(apci + 1);

  /* Grab all 104 packets. */
  if(START == apci->start) {

    if (trigger >= 11) {
      trigger = 0;
    } else {
      trigger++;
    }

    /* we can't inject in unoffensive mode or in bridge mode */
    if (GBL_OPTIONS->unoffensive || GBL_OPTIONS->read || GBL_OPTIONS->iface_bridge) {
          USER_MSG("\n[!!] We can't inject in unoffensive mode or in bridge mode.\n");
      return -EINVALID;
    } 

    /* Prevent the packet being sent */
    po->flags ^= PO_DROPPED;

    switch(trigger){
      case INVALID_START:
      /* Trigger 6666601 */
      apci->start = 0x42;
      USER_MSG("%s\n", triggers[INVALID_START]);
      break;

      case TYPE_ID_INVALID_CONTROL_DIR:
      /* Trigger 6666611 - When a packet comes from the client. */
      if (ntohs(po->L4.dst) == 2404) {
        asdu->type_id = 0x1F;  /* 31 */
      }
      
      USER_MSG("%s\n", triggers[TYPE_ID_INVALID_CONTROL_DIR]);
      break;

      case TYPE_ID_INVALID_MONITOR_DIR:
      /* Trigger 6666612 */
      if (ntohs(po->L4.dst) != 2404) {
        asdu->type_id = 0x7E;  /* 126 */
      }

      USER_MSG("%s\n", triggers[TYPE_ID_INVALID_MONITOR_DIR]);
      break;

      case SPON_COT:
      /* Trigger 6666602 */
      asdu->COT = 0x03; /* Needs more packets to trigger */
      USER_MSG("%s\n", triggers[SPON_COT]);
      break;

      case INVALID_COT:
      /* Trigger 6666617 - Default to catch and from the client. */ 
      asdu->COT = 0x2A;     /* Invalid */
      USER_MSG("%s\n", triggers[INVALID_COT]);
      break;

      case INVALID_COT_45:
      /* Trigger 6666618 */
      asdu->type_id = 0x2D; /* 45 */
      asdu->COT = 0x2A;     /* Invalid */
      USER_MSG("%s\n", triggers[INVALID_COT_45]);
      break;

      case INVALID_COT_01:
      /* Trigger 6666619 */
      asdu->type_id = 0x01; /* 01 */
      asdu->COT = 0x2A;     /* Invalid */
      USER_MSG("%s\n", triggers[INVALID_COT_01]);
      break;

      case INVALID_COT_15:
      /* Trigger 6666620 */
      asdu->type_id = 0xF; /* 15 */
      asdu->COT = 0x2A;     /* Invalid */
      USER_MSG("%s\n", triggers[INVALID_COT_15]);
      break;

      case INVALID_COT_32:
      /* Trigger 6666621 */
      asdu->type_id = 0x20; /* 32 */
      asdu->COT = 0x2A;     /* Invalid */
      USER_MSG("%s\n", triggers[INVALID_COT_32]);
      break;

      case TYPE_ID_RESET:
      /* Trigger 6666608 */
      asdu->type_id = RESET; 
      USER_MSG("%s\n", triggers[TYPE_ID_RESET]);
      break;

      case BROADCAST_ADDRESS:
      /* Trigger 6666609 */
      asdu->originator_addr = BROADCAST;
      USER_MSG("%s\n", triggers[BROADCAST_ADDRESS]);
      break;

      case INVALID_LENGTH:
      /*Trigger 6666613/15/16 - Causes the conenction the be reset WinPP's error. */
      apci->length = 15;
      USER_MSG("%s\n", triggers[INVALID_LENGTH]);
      break;

    }
    /* PACKET SIZE TO LONG */

    // USER_MSG("%d ->", po->DATA.disp_len);
    // memcpy(po->DATA.data, apci, sizeof(apci));
    // memcpy(po->DATA.data + sizeof(struct apci_header), asdu, sizeof(asdu));
    // memcpy(po->DATA.data + sizeof(struct apci_header) + sizeof(apci), "PETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETE", sizeof("PETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETEPETE"));
    // po->DATA.disp_len = 512;
    // USER_MSG("%d\n", po->DATA.disp_len);

    /* PACKET SIZE TO LONG */

    /* Change the IP address */

    // char ip_str = "10.50.50.5";
    // struct in_addr ipaddr;
    // struct ip_addr ip;

    // if (inet_pton(AF_INET, &ip_str, &ipaddr) == 1) {
    //   USER_MSG("[!!] Unable to parse new IP address.\n");
    // }

    // if (ip_addr_init(&ip, AF_INET, (u_char *)&ipaddr) == 1) {
    //   USER_MSG("[!!] Unable to set new IP address.\n");
    // }
    // send_tcp(&ip, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_ACK, po->DATA.data,po->DATA.disp_len );

    /* Change the IP address */

    /* Send modified packet */
    // send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_ACK, po->DATA.data,po->DATA.disp_len );
    // USER_MSG("\n%d -> %d <> ", ntohs(po->L4.dst), ntohs(po->L4.src));
    // send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_ACK, po->DATA.data,po->DATA.disp_len );

    // if (ntohs(po->L4.dst) == 2404) {
    //   po->L4.dst = htons(1337);
    // }
    send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_ACK, po->DATA.data,po->DATA.disp_len );
    // USER_MSG("%d -> %d\n", ntohs(po->L4.dst), ntohs(po->L4.src));
    // sleep(100);

  }
}

/* Read the first two bits from from the control octet 1
   Return the result based on the values */
static int get_type(u_int8 control)
{
    int one = ((control & 1<<0)==0 ? false : true); 
    int two = ((control & 1<<1)==0 ? false : true);

    if(one == 0)
      return I_FORMAT;
    if(one == 1 & two == 0)
      return S_FORMAT;
    if(one == 1 & two == 1)
      return U_FORMAT;
    return -1;
}

/* Debug print messages */
static void print_apci(struct apci_header *apci)
{
  USER_MSG("\n[-] APCI\n[+] START: \t%x \n[+] Length: \t%d \n[+] Control 1: \t%x \n[+] Control 2: \t%x \n[+] Control 3: \t%x \n[+] Control 4: \t%x \n[+] Type: \t%d\n", 
      apci->start, apci->length, apci->control_1, apci->control_2, apci->control_3, apci->control_4, get_type(apci->control_1));
}

static void print_asdu(struct asdu_header *asdu)
{
  USER_MSG("\n[-] ASDU\n[+] TC:\t\t 0x%x <%d> \n[+] SQ:\t\t %x \n[+] COT:\t %d \n[+] PN:\t\t %x \n[+] T:\t\t %x \n[+] O-Addr:\t %d \n[+] IOA:\t %d \n", 
    asdu->type_id, asdu->type_id, asdu->sq, asdu->COT, asdu->PN, asdu->T, asdu->originator_addr, asdu->IOA);
  USER_MSG("\n[*] SPI: %d - BL: %d - SB: %d - NT: %d - IV: %d\n",
    asdu->spi, asdu->bl, asdu->sb, asdu->nt, asdu->iv);
}

/* EOF */

// vim:ts=3:expandtab

