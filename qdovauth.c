/*
** Authenticate qmail smtp/submission using doveadm.
** This program reads from fd 3 username & password and 
** authenticates against Dovecot. Dovecot can be configured 
** to authenticate against most anything.
**
** Program:
**    qdovauth
**
** Source
**    qdovauth.c
**
** Build:
**    gcc -o qdovauth qdovauth.c
**    Move to /home/vpopmail/bin
**    chown vpopmail:vchkpw /home/vpopmail/bin/qdovauth
**    chmod 755 /home/vpopmail/bin/qdovauth
**    ls -l /home/vpopmail/bin/qdovauth
**      -rwxr-xr-x. 1 vpopmail vchkpw 23168 Apr 11 23:44 /home/vpopmail/bin/qdovauth
**
** Use:
**   Edit submission/smtps run files:
**     #VCHKPW="/home/vpopmail/bin/vchkpw"
**     VCHKPW="/home/vpopmail/bin/qdovauth"
**   # qmailctl stop
**   # qmailctl start
**
** Dovecot:
**   Add the below services to your dovecot configuration and restart
** service stats {
**    unix_listener stats-reader {
**    user = vpopmail
**    group = vchkpw
**    mode = 0660
**    }
**    unix_listener stats-writer {
**    user = vpopmail
**    group = vchkpw
**    mode = 0660
**    }
** } 
**
** service auth {
**   unix_listener auth-qmail {
**   mode = 0600
**   user = vpopmail
**   group = vchkpw
**   }
** }
** # systemctl restart dovecot
**
** Programmer:
**    Eric C. Broch
**    ebroch@whitehorsetc.com
**
** Date:
**    04-10-2024
**
** License:
**    None
**
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <syslog.h>

#define CLEAN       0  // clean execution of parent and child
#define CREDFILE    3  // Credentials file from qmail-smtpd
#define DAUNAVAIL -10  // doveadm unavailable
#define FRKFAIL   -11  // fork failed
#define EXECFAIL  -12  // child executable failed
#define CREDFAIL  -13  // Failed to read credentials from fd 3
#define UPFAIL    -14  // Failed to read user
#define PASSFAIL  -15  // Failed to read password
#define CHALFAIL  -16  // Failed to read challenge

#define AUTHSIZE 1000
char buf[AUTHSIZE];
char *user = NULL;
char *pass = NULL;
char *chal = NULL;
char *doveadm = "/usr/bin/doveadm";

void read_credentials();
char *rjunk(char *text);

int main( int argc, char *argv[] )
{
   char *success = "succeeded";
   int status;
   int fd[2];
   int nbytes;
   char  buff[1024];

   char *alog = getenv("QDOVAUTH_LOG");
   if ( alog ) openlog("qdovauth",LOG_PID,LOG_MAIL);
   if ( access(doveadm,F_OK) ) {
      if ( alog) syslog(LOG_NOTICE,"Dovecot's doveadm program does not exist");
      exit(DAUNAVAIL);
   }
   read_credentials();
   char *command[] = {doveadm,"auth","test","-a","/var/run/dovecot/auth-qmail",user,pass,NULL};

   pipe(fd);
   pid_t pid = fork();
   if ( pid < 0 ) {
      if ( alog ) syslog(LOG_NOTICE,"%s","Fork failed");
      exit(FRKFAIL);
   }
   // Parent
   else if (pid > 0) {
      close(fd[1]);                           // Parent process closes up output side of pipe
      memset(buff,'\0',sizeof(buff));
      nbytes = read(fd[0],buff,sizeof(buff)); // Read output from child call to doveadm may eventually log/debug
      if ( alog ) {
         char * p = strstr(buff,"extra fields");
         if ( p ) buff[p-buff-1]  = '\0';
         p = getenv("TCPREMOTEIP");
         if ( !p ) p = "UNKNOWN HOST";
         syslog(LOG_NOTICE, "%s:IP:%s",rjunk(buff),p);
      }
      waitpid(pid, &status, 0);
      if ( WIFEXITED(status) ) {
         const int es = WEXITSTATUS(status);
         if ( es ) exit(es);
      }
   }
   // Child
   else {
      close(fd[0]);         // Child process closes up input side of pipe
      dup2(fd[1],1);        // Send stdout from doveadm back to parent, we may want to do something with it, log perhaps.
      dup2(fd[1],2);        // Send stderr from doveadm back to parent. we may want to do something with it, log perhaps.
      execvp(command[0],command);
      _exit(EXECFAIL);      // exec should never return
   }
   execvp(argv[1],argv+1);  // Run next program
   exit(CLEAN);             // Authentication succeeded
}

// Remove non-printable characters from text
char *rjunk(char *text)
{
  for(char *new=text;*new!=0;++new) if ( *new < 32 || *new > 126 ) *new = ' ';
  return(text);
}
// Read username and password from fd 3, qmail-smtpd
void read_credentials()
{

  memset(buf,'\0',AUTHSIZE);
  ssize_t bufsz = read(CREDFILE,buf,AUTHSIZE);
  if ( bufsz <= 0 ) exit(CREDFAIL);
  close(CREDFILE);

  user=buf;
  if ( strchr(user,'\0') ) pass=(strchr(user,'\0'))+1;
  else exit(PASSFAIL);
  if ( strchr(pass,'\0') ) chal=(strchr(pass,'\0'))+1;
  else exit(CHALFAIL);
  if ( strlen(user) <= 0 || strlen(pass) <= 0 ) exit(UPFAIL);

}
