/*
    ettercap -- session management

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

    $Id: ec_session.c,v 1.5 2003/07/01 19:15:44 alor Exp $
*/

#include <ec.h>
#include <ec_packet.h>
#include <ec_threads.h>
#include <ec_session.h>

#include <signal.h>

struct session_list {
   pthread_t id;
   time_t ts;
   struct session *s;
   LIST_ENTRY (session_list) next;
};

/* global data */

static LIST_HEAD(, session_list) session_list_head;

/* protos */

void session_put(struct session *s);
int session_get(struct session **s, void *ident);
int session_del(void *ident);
int session_get_and_del(struct session **s, void *ident);

void session_free(struct session *s);

#ifdef DEBUG
void __init session_handler(void);
static void session_dump(int sig);
#endif

static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;
#define SESSION_LOCK     do{ pthread_mutex_lock(&session_mutex); } while(0)
#define SESSION_UNLOCK   do{ pthread_mutex_unlock(&session_mutex); } while(0)

/************************************************/

/*
 * create a session if it does not exits
 * update a session if it already exists
 *
 * also check for timeouted session and remove them
 */

void session_put(struct session *s)
{
   struct session_list *sl, *old = NULL;
   time_t ti = time(NULL);

   SESSION_LOCK;
   
   /* search if it already exist */
   LIST_FOREACH(sl, &session_list_head, next) {
      /* sessions are unique per thread */
      if ( sl->id == pthread_self() && sl->s->match(sl->s->ident, s->ident) ) {

         DEBUG_MSG("session_put: [%d][%p] updated", sl->id, sl->s->ident);
         /* destroy the old session */
         session_free(sl->s);
         /* link the new session */
         sl->s = s;
         /* renew the timestamp */
         sl->ts = ti;
         
         SESSION_UNLOCK;
         return;
      }

      /* delete timeouted sessions */

      SAFE_FREE(old);
      
      if (sl->ts < (ti - GBL_CONF->connection_timeout) ) {
         DEBUG_MSG("session_put: [%d][%p] timeouted", sl->id, sl->s->ident);
         session_free(sl->s);
         LIST_REMOVE(sl, next);
         /* remember the pointer and free it the next loop */
         old = sl;
      }
   }
   
   /* if it was the last element, free it */   
   SAFE_FREE(old);

   /* sanity check */
   BUG_IF(s->match, NULL);
  
   /* create the element in the list */
   sl = calloc(1, sizeof(struct session_list));
   ON_ERROR(sl, NULL, "can't allocate memory");

   /* mark the session for the current thread */
   sl->id = pthread_self();

   /* the timestamp */
   sl->ts = ti;

   /* link the session */
   sl->s = s;
   
   DEBUG_MSG("session_put: [%d][%p] new session", sl->id, sl->s->ident);

   /* 
    * put it in the head.
    * it is likely to be retrived early
    */
   LIST_INSERT_HEAD(&session_list_head, sl, next);

   SESSION_UNLOCK;
  
}


/*
 * get the info contained in a session
 */

int session_get(struct session **s, void *ident)
{
   struct session_list *sl;

   SESSION_LOCK;
   
   /* search if it already exist */
   LIST_FOREACH(sl, &session_list_head, next) {
      if ( sl->id == pthread_self() && sl->s->match(sl->s->ident, ident) ) {
   
         DEBUG_MSG("session_get: [%d][%p]", sl->id, sl->s->ident);
         /* return the session */
         *s = sl->s;

         SESSION_UNLOCK;
         return ESUCCESS;
      }
   }
   
   SESSION_UNLOCK;
   
   return -ENOTFOUND;
}


/*
 * delete a session
 */

int session_del(void *ident)
{
   struct session_list *sl;

   SESSION_LOCK;
   
   /* search if it already exist */
   LIST_FOREACH(sl, &session_list_head, next) {
      if ( sl->id == pthread_self() && sl->s->match(sl->s->ident, ident) ) {
         
         DEBUG_MSG("session_del: [%d][%p]", sl->id, sl->s->ident);

         /* free the session */
         session_free(sl->s);
         /* remove the element in the list */
         LIST_REMOVE(sl, next);
         /* free the element in the list */
         SAFE_FREE(sl);

         SESSION_UNLOCK;
         return ESUCCESS;
      }
   }
   
   SESSION_UNLOCK;
   
   return -ENOTFOUND;
}


/*
 * get the info and delete the session
 * atomic operations
 */

int session_get_and_del(struct session **s, void *ident)
{
   struct session_list *sl;

   SESSION_LOCK;
   
   /* search if it already exist */
   LIST_FOREACH(sl, &session_list_head, next) {
      if ( sl->id == pthread_self() && sl->s->match(sl->s->ident, ident) ) {
         
         DEBUG_MSG("session_get_and_del: [%d][%p]", sl->id, sl->s->ident);
         
         /* return the session */
         *s = sl->s;
         /* remove the element in the list */
         LIST_REMOVE(sl, next);
         /* free the element in the list */
         SAFE_FREE(sl);

         SESSION_UNLOCK;
         return ESUCCESS;
      }
   }
   
   SESSION_UNLOCK;
   
   return -ENOTFOUND;
}

/*
 * free a session structure
 */

void session_free(struct session *s)
{
   SAFE_FREE(s->ident);
   SAFE_FREE(s->data);
   SAFE_FREE(s);
}

#ifdef DEBUG
/*
 * dump the list of all active sessions.
 * only for debugging purpose.
 * use 'killall -HUP ettercap' to dump the list.
 */

void __init session_handler(void)
{
   signal(SIGHUP, session_dump);
}

static void session_dump(int sig)
{
   struct session_list *sl;

   DEBUG_MSG("session_dump invoked: dumping the session list...");
   
   SESSION_LOCK;
   
   /* dump the list in the debug file */
   LIST_FOREACH(sl, &session_list_head, next) {
         
      DEBUG_MSG("session_dump: [%d][%p]", sl->id, sl->s->ident);
         
   }
   
   SESSION_UNLOCK;
}

#endif

/* EOF */

// vim:ts=3:expandtab

