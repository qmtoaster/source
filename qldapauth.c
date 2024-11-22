#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <iostream>
#include <ldap.h>

#define CLEAN       0  // clean execution of parent and child
#define CREDFILE    3  // Credentials file from qmail-smtpd
#define DAUNAVAIL -10  // doveadm unavailable
#define FRKFAIL   -11  // fork failed
#define EXECFAIL  -12  // child executable failed
#define CREDFAIL  -13  // Failed to read credentials from fd 3
#define UPFAIL    -14  // Failed to read user
#define PASSFAIL  -15  // Failed to read password
#define CHALFAIL  -16  // Failed to read challenge
#define DOMFAIL   -17  // Failed to read domain

#define AUTHSIZE 1000
char buf[AUTHSIZE];
char *user = NULL;
char *pass = NULL;
char *chal = NULL;
char *host = NULL;
char *dom  = NULL;
int  port;

void read_credentials();
char *itoa( int port, char *ldapport );
int auth(char *username,char *password,char *host,char *domain,int *port);

int main( int argc, char *argv[] )
{
   openlog("qldapauth",LOG_PID,LOG_MAIL);
   host = getenv("LDAP_HOST");
   port = atoi( (getenv("LDAP_PORT")) ? : "");
   read_credentials();
   int authret = auth(user, pass, host, dom, &port);
   closelog();
   if ( authret != LDAP_SUCCESS ) exit(authret);
   execvp(argv[1],argv+1);
   exit(LDAP_SUCCESS);
}
// Read username and password from fd 3, qmail-smtpd
void read_credentials()
{

  memset(buf,'\0',AUTHSIZE);
  ssize_t bufsz = read(CREDFILE,buf,AUTHSIZE);
  if ( bufsz <= 0 ) { syslog(LOG_INFO,"Failure reading credentials for fd 3"); exit(CREDFAIL);}
  close(CREDFILE);

  buf[strchr(buf,'@')-buf] = '\0';
  user=buf;
  if ( strchr(user,'\0') ) dom=(strchr(user,'\0'))+1;
  if ( strchr(dom,'\0') ) pass=(strchr(dom,'\0'))+1;
  if ( strchr(pass,'\0') ) chal=(strchr(pass,'\0'))+1;

}
int auth(char *username,char *password,char *host,char *domain,int *port)
{

   // Security Guards
   if (!username || !password || !host || !domain || *port == 0)
   {
      syslog(LOG_NOTICE,"Missing value(s): username, password, host, domain or port");
      return LDAP_OTHER;
   }

   // Declarations
   int conn_status, version(LDAP_VERSION3), bind, unbind;
   LDAP *ld;
   char email[200];
   char ldapurl[300];
   char ldapport[4];

   // ldap url
   memset(ldapurl,'\0',sizeof(ldapurl));
   strcpy(ldapurl,"ldap://");
   strcat(ldapurl,host);
   strcat(ldapurl,":");
   strcat(ldapurl,itoa(*port,ldapport));

   conn_status = ldap_initialize(&ld, ldapurl);
   if (conn_status != LDAP_SUCCESS)
   {
      syslog(LOG_NOTICE,"Error Code = %d, Message = %s",conn_status,ldap_err2string(conn_status));
   }
   ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

   // Append domain to username
   memset(email,'\0',sizeof(email));
   strcpy(email,username);
   strcat(email,"@");
   strcat(email,domain);

   // Execute bind
   berval credentials;
   berval *srv = NULL;
   credentials.bv_val = password;
   credentials.bv_len = strlen(password);

   char *remote = getenv("TCPREMOTEIP");
   if ( !remote ) remote  = (char*)"UNKNOWN HOST";
   if ( ( bind = ldap_sasl_bind_s(ld,email,LDAP_SASL_SIMPLE,&credentials,NULL,NULL,&srv) ) == LDAP_SUCCESS ) {
      syslog(LOG_NOTICE,"Auth succeded for: %s:%s",email,remote);
      if ( ( unbind = ldap_unbind_ext_s(ld, NULL, NULL) ) != LDAP_SUCCESS) {
         syslog(LOG_NOTICE,"Unbind failed. Error Code: %d, Message: %s",unbind,ldap_err2string(bind));
      }
   }
   else {
      syslog(LOG_NOTICE,"Auth failed for %s:%s, Error Code: %d, Message: %s",email,remote,bind,ldap_err2string(bind));
   }
   return bind;
}
char * itoa( int port, char *ldapport )
{
   sprintf(ldapport,"%d",port);
   return ldapport;
}
