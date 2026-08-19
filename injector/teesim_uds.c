// teesim-uds — the WebUI's transport to the control daemon's admin endpoint.
//
// The daemon (KeyAdmin) used to listen on a loopback TCP port (127.0.0.1:8790) that the WebUI reached
// with a browser fetch(). Any app on the device could connect() to that port, and the mere fact that
// something answered there fingerprinted the module. The daemon now serves on a FILESYSTEM unix-domain
// socket under /data/adb/teesim (a 0700, root-only directory), so the kernel refuses a connect() from
// any non-root uid before a byte is exchanged: to every other app the endpoint simply does not exist.
//
// A WebView cannot fetch() a unix socket, so the WebUI drives this tiny client through its root-exec
// bridge instead. It speaks the same HTTP/1.1 the daemon already parses, so the server side keeps its
// existing request routing — only the socket underneath changed.
//
//   teesim-uds SOCK METHOD PATH TOKEN [--b64] [--body-file FILE]
//
//     SOCK        filesystem path of the daemon's admin socket
//     METHOD      GET | POST
//     PATH        request target, e.g. "/status" or "/icon?pkg=com.foo&user=0"
//     TOKEN       the admin token (sent as X-Teesim-Token; the socket perms are the real gate)
//     --b64       base64-encode the response body on stdout (for binary payloads, e.g. icons)
//     --body-file read the request body from FILE and send it with a Content-Length
//
// stdout: the response body (raw, or base64 with --b64). stderr: diagnostics only.
// exit:   0 = HTTP 2xx, 2 = HTTP response with a non-2xx status (body still written),
//         1 = usage / connect / I/O error (nothing written to stdout).

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static void die(const char *msg) {
  fprintf(stderr, "teesim-uds: %s: %s\n", msg, strerror(errno));
  exit(1);
}

// Read a whole file into a freshly malloc'd buffer. *len gets the byte count. Caller frees.
static char *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) die("open body-file");
  if (fseek(f, 0, SEEK_END) != 0) die("seek body-file");
  long sz = ftell(f);
  if (sz < 0) die("tell body-file");
  rewind(f);
  char *buf = malloc((size_t)sz + 1);
  if (!buf) die("malloc body");
  size_t got = fread(buf, 1, (size_t)sz, f);
  fclose(f);
  buf[got] = '\0';
  *len = got;
  return buf;
}

// Drain the socket into a growing heap buffer until EOF. *len gets the byte count.
static char *read_all(int fd, size_t *len) {
  size_t cap = 16 * 1024, n = 0;
  char *buf = malloc(cap);
  if (!buf) die("malloc response");
  for (;;) {
    if (n == cap) {
      cap *= 2;
      char *nb = realloc(buf, cap);
      if (!nb) die("realloc response");
      buf = nb;
    }
    ssize_t r = read(fd, buf + n, cap - n);
    if (r < 0) {
      if (errno == EINTR) continue;
      die("read response");
    }
    if (r == 0) break;
    n += (size_t)r;
  }
  *len = n;
  return buf;
}

static void write_all(int fd, const char *buf, size_t len) {
  size_t off = 0;
  while (off < len) {
    ssize_t w = write(fd, buf + off, len - off);
    if (w < 0) {
      if (errno == EINTR) continue;
      die("write");
    }
    off += (size_t)w;
  }
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64-encode src to stdout. Used for binary bodies (--b64) so the shell captures clean text.
static void b64_stdout(const unsigned char *src, size_t len) {
  size_t i = 0;
  char out[4];
  for (; i + 3 <= len; i += 3) {
    unsigned v = (src[i] << 16) | (src[i + 1] << 8) | src[i + 2];
    out[0] = B64[(v >> 18) & 63];
    out[1] = B64[(v >> 12) & 63];
    out[2] = B64[(v >> 6) & 63];
    out[3] = B64[v & 63];
    fwrite(out, 1, 4, stdout);
  }
  size_t rem = len - i;
  if (rem == 1) {
    unsigned v = src[i] << 16;
    out[0] = B64[(v >> 18) & 63];
    out[1] = B64[(v >> 12) & 63];
    out[2] = '=';
    out[3] = '=';
    fwrite(out, 1, 4, stdout);
  } else if (rem == 2) {
    unsigned v = (src[i] << 16) | (src[i + 1] << 8);
    out[0] = B64[(v >> 18) & 63];
    out[1] = B64[(v >> 12) & 63];
    out[2] = B64[(v >> 6) & 63];
    out[3] = '=';
    fwrite(out, 1, 4, stdout);
  }
}

int main(int argc, char **argv) {
  if (argc < 5) {
    fprintf(stderr, "usage: teesim-uds SOCK METHOD PATH TOKEN [--b64] [--body-file FILE]\n");
    return 1;
  }
  const char *sock = argv[1];
  const char *method = argv[2];
  const char *path = argv[3];
  const char *token = argv[4];
  int b64 = 0;
  const char *body_file = NULL;
  for (int i = 5; i < argc; i++) {
    if (strcmp(argv[i], "--b64") == 0) {
      b64 = 1;
    } else if (strcmp(argv[i], "--body-file") == 0 && i + 1 < argc) {
      body_file = argv[++i];
    } else {
      fprintf(stderr, "teesim-uds: unknown argument '%s'\n", argv[i]);
      return 1;
    }
  }

  char *body = NULL;
  size_t body_len = 0;
  if (body_file) body = read_file(body_file, &body_len);

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) die("socket");
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  if (strlen(sock) >= sizeof(addr.sun_path)) {
    fprintf(stderr, "teesim-uds: socket path too long\n");
    return 1;
  }
  strncpy(addr.sun_path, sock, sizeof(addr.sun_path) - 1);
  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) die("connect");

  // Build and send the request head. The token gates the endpoint at the app layer; the socket's
  // filesystem permissions gate it at the kernel layer. Connection: close so the server's read_all
  // sees a clean EOF.
  char head[8192];
  int hn;
  if (body_file) {
    hn = snprintf(head, sizeof(head),
                  "%s %s HTTP/1.1\r\nHost: localhost\r\nX-Teesim-Token: %s\r\n"
                  "Content-Type: text/plain; charset=utf-8\r\nContent-Length: %zu\r\n"
                  "Connection: close\r\n\r\n",
                  method, path, token, body_len);
  } else {
    hn = snprintf(head, sizeof(head),
                  "%s %s HTTP/1.1\r\nHost: localhost\r\nX-Teesim-Token: %s\r\nConnection: close\r\n\r\n",
                  method, path, token);
  }
  if (hn < 0 || (size_t)hn >= sizeof(head)) {
    fprintf(stderr, "teesim-uds: request head too large\n");
    return 1;
  }
  write_all(fd, head, (size_t)hn);
  if (body_len) write_all(fd, body, body_len);
  shutdown(fd, SHUT_WR);
  free(body);

  size_t resp_len = 0;
  char *resp = read_all(fd, &resp_len);
  close(fd);

  // Split headers from body at the blank line, and read the status code off the response line.
  int status = 0;
  if (resp_len >= 12 && strncmp(resp, "HTTP/1.", 7) == 0) status = atoi(resp + 9);
  char *sep = NULL;
  for (size_t i = 0; i + 4 <= resp_len; i++) {
    if (resp[i] == '\r' && resp[i + 1] == '\n' && resp[i + 2] == '\r' && resp[i + 3] == '\n') {
      sep = resp + i + 4;
      break;
    }
  }
  const char *bstart = sep ? sep : resp;
  size_t blen = sep ? resp_len - (size_t)(sep - resp) : resp_len;

  if (b64) {
    b64_stdout((const unsigned char *)bstart, blen);
  } else {
    write_all(STDOUT_FILENO, bstart, blen);
  }
  fflush(stdout);
  free(resp);

  if (status >= 200 && status < 300) return 0;
  return 2;
}
