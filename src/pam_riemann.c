/* pam_riemann module */

/*
 *
 *  pam_riemann.c
 *
 *  Created on: 05/apr/2017
 *      Author: ronga
 */


/*
 *  TODO List:
 *
 *
 */

#define UNUSED __attribute__ ((unused))
#define MAXHOSTNAMEL 255

#include <riemann/riemann-client.h>
#include <riemann/simple.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>

/*
 * here, we make a definition for the externally accessible function
 * in this file (this definition is required for static a module
 * but strongly encouraged generally) it is used to instruct the
 * modules include file to define the function prototypes.
 */

#define PAM_SM_AUTH
#define PAM_SM_PASSWORD

#include <security/pam_modules.h>
#include <security/pam_ext.h>

/* some syslogging */

#define OBTAIN(item, value, default_value)  do {                \
     (void) pam_get_item(pamh, item, &value);                   \
     value = value ? value : default_value ;                    \
} while (0)


static int parse_args(pam_handle_t *pamh, const char **riemann_server,
		int *riemann_port, int argc, const char **argv)
{
	int i;

    for (i=0; i<argc; ++i) {

    	if (!strncmp("server=", argv[i], 7)) {

    		*riemann_server = argv[i]+7;
    		if (**riemann_server == '\0') {
    			*riemann_server = NULL;
        		pam_syslog(pamh, LOG_ERR, "riemann server hostname invalid");
        		return -1;

    		}

    	} else if (!strncmp("port=", argv[i], 5)) {

    		sscanf(argv[i]+5,"%d",riemann_port);

    	} else {
    		pam_syslog(pamh, LOG_ERR, "unrecognized option [%s]", argv[i]);
    		return -1;
    	}
    }

    pam_syslog(pamh,LOG_NOTICE,"Riemann server=%s port=%d",*riemann_server,*riemann_port);
	return 0;
}


/*static void log_items(pam_handle_t *pamh, const char *function, int flags)
{
     const void *service=NULL, *user=NULL, *terminal=NULL,
	 *rhost=NULL, *ruser=NULL;

     OBTAIN(PAM_SERVICE, service, "<unknown>");
     OBTAIN(PAM_TTY, terminal, "<unknown>");
     OBTAIN(PAM_USER, user, "<unknown>");
     OBTAIN(PAM_RUSER, ruser, "<unknown>");
     OBTAIN(PAM_RHOST, rhost, "<unknown>");

     pam_syslog(pamh, LOG_NOTICE,
		" function=[%s] flags=%#x service=[%s] terminal=[%s] user=[%s]"
		" ruser=[%s] rhost=[%s]\n", function, flags,
		(const char *) service, (const char *) terminal,
		(const char *) user, (const char *) ruser,
		(const char *) rhost);
}*/

static void log_riemann_errors(pam_handle_t *pamh, const char *error_text)
{
	pam_syslog(pamh, LOG_ERR, "(lsr2017) : Riemann connection : %s", error_text);
}


static int send_riemann_event(pam_handle_t *pamh, const char *riemann_server, int riemann_port)
{
	riemann_client_t *client;
	riemann_message_t *r;
	char hostname[MAXHOSTNAMEL+1];

	const void *pam_service=NULL, *pam_user=NULL, *pam_terminal=NULL, *pam_rhost=NULL, *pam_ruser=NULL;

	/* connect to riemann server */
	client = riemann_client_create (RIEMANN_CLIENT_UDP, riemann_server, riemann_port);
	if (!client)
	{
		log_riemann_errors(pamh, "failed to connect to riemann server");
		return -1;
	}

	/* get login information */
	OBTAIN(PAM_SERVICE, pam_service, "<unknown>");
	OBTAIN(PAM_TTY, pam_terminal, "<unknown>");
	OBTAIN(PAM_USER, pam_user, "<unknown>");
	OBTAIN(PAM_RUSER, pam_ruser, "<unknown>");
	OBTAIN(PAM_RHOST, pam_rhost, "<unknown>");

	/* get the hostname */
	if (gethostname(hostname, MAXHOSTNAMEL)) {
		log_riemann_errors(pamh, "failed to retrieve hostname");
		return -1;
	}


	r = riemann_communicate_event
			(client,
					RIEMANN_EVENT_FIELD_HOST, hostname,
					RIEMANN_EVENT_FIELD_SERVICE, "pam_riemann",
					RIEMANN_EVENT_FIELD_STATE, "ok",
					RIEMANN_EVENT_FIELD_TAGS, "pam_riemann", "login_event", NULL,
					RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
						"login-rhost", (char *)pam_rhost,
						"login-user", (char *)pam_user,
						NULL,
					RIEMANN_EVENT_FIELD_NONE);

	if (!r)
	{
		log_riemann_errors(pamh, "failed to send to riemann server");
		return -1;
	}

	if (r->ok != 1)
	{
		log_riemann_errors(pamh, "failed communication with riemann server");
		return -1;
	}

	riemann_message_free (r);
	riemann_client_free (client);

	return 0;

}
/* --- authentication management functions (only) --- */

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{


	const char *riemann_server = "localhost";
	int riemann_port = 5555;

	/* parse the arguments */
	parse_args(pamh, &riemann_server, &riemann_port, argc, argv);

	/* send riemann event */
	if (!send_riemann_event(pamh, riemann_server, riemann_port))
		log_riemann_errors(pamh, "correctly sent to riemann server");

	/*log_items(pamh, __FUNCTION__, flags);*/
	return PAM_IGNORE;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc UNUSED, const char **argv UNUSED)
{
    /* log_items(pamh, __FUNCTION__, flags); */
    return PAM_IGNORE;
}

/* password updating functions */

int pam_sm_chauthtok(pam_handle_t *pamh, int flags,
		     int argc UNUSED, const char **argv UNUSED)
{
    /*log_items(pamh, __FUNCTION__, flags);*/
    return PAM_IGNORE;
}

int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
		 int argc UNUSED, const char **argv UNUSED)
{
    /*log_items(pamh, __FUNCTION__, flags);*/
    return PAM_IGNORE;
}

int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc UNUSED, const char **argv UNUSED)
{
    /* log_items(pamh, __FUNCTION__, flags);*/
    return PAM_IGNORE;
}

int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc UNUSED, const char **argv UNUSED)
{
    /* log_items(pamh, __FUNCTION__, flags);*/
    return PAM_IGNORE;
}

/* end of module definition */
