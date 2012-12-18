/*
 * connect_ssh.c
 * This file connects to a SSH server using libssh
 */
#include <stdio.h>

ssh_session connect_ssh(const char *host, const char *user, char *port, int verbosity){
  ssh_session session;

  session=ssh_new();
  if (session == NULL) {
    return NULL;
  }

  if(user != NULL && ssh_options_set(session, SSH_OPTIONS_USER, user) < 0)
    goto terminate;

  if(port != NULL && ssh_options_set(session, SSH_OPTIONS_PORT_STR, port) < 0)
    goto terminate;

  if (ssh_options_set(session, SSH_OPTIONS_HOST, host) < 0)
    goto terminate;

  ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  if(ssh_connect(session)){
    fprintf(stderr,"Connection failed : %s\n",ssh_get_error(session));
    ssh_disconnect(session);
    goto terminate;
  }
  if(verify_knownhost(session)<0){
    ssh_disconnect(session);
    goto terminate;
  }
  int auth = authenticate(session);
  if(auth == SSH_AUTH_SUCCESS){
    return session;
  } else if(auth == SSH_AUTH_DENIED){
    fprintf(stderr,"Authentication failed\n");
  } else {
    fprintf(stderr,"Error while authenticating : %s\n",ssh_get_error(session));
  }
  ssh_disconnect(session);

terminate:  
  ssh_free(session);
  return NULL;
}
