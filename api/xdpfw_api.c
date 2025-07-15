#include "mongoose.h"
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

/* Concatenate strings safely */
static void scat(char *dst, const char *src, size_t siz)
{
    size_t len = strlen(dst);
    if (len < siz - 1)
    {
        strncat(dst, src, siz - len - 1);
    }
}

static const char *DB_PATH = "api/filters.db";
static const char *ADD_BIN = "/usr/bin/xdpfw-add";
static const char *DEL_BIN = "/usr/bin/xdpfw-del";
static const char *AUTH_TOKEN = "changeme";
static sqlite3 *db;

// Execute shell command and capture exit code
static int run_cmd(const char *cmd) {
  return system(cmd);
}

// Convert JSON body to CLI arguments string
static void json_to_args(struct mg_str body, char *buf, size_t len) {
  struct mg_str key, val;
  size_t ofs = 0;
  buf[0] = '\0';
  while ((ofs = mg_json_next(body, ofs, &key, &val)) > 0) {
    char k[64], v[64];
    mg_json_unescape(key, k, sizeof(k));
    mg_json_unescape(val, v, sizeof(v));
    if (strcmp(v, "true") == 0) strcpy(v, "1");
    else if (strcmp(v, "false") == 0) strcpy(v, "0");
    if (buf[0] != '\0') scat(buf, " ", len);
    char tmp[128];
    snprintf(tmp, sizeof(tmp), "--%s=%s", k, v);
    scat(buf, tmp, len);
  }
}

// Apply filter using CLI tool
static int apply_filter(int idx, const char *json) {
  char args[512];
  json_to_args(mg_str(json), args, sizeof(args));
  char cmd[1024];
  snprintf(cmd, sizeof(cmd), "%s --idx=%d %s", ADD_BIN, idx, args);
  return run_cmd(cmd);
}

static int remove_filter(int idx) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "%s --idx=%d", DEL_BIN, idx);
  return run_cmd(cmd);
}

// Initialize database
static void init_db(void) {
  if (sqlite3_open(DB_PATH, &db) != SQLITE_OK) {
    fprintf(stderr, "Failed to open DB\n");
    exit(1);
  }
  const char *sql = "CREATE TABLE IF NOT EXISTS filters (idx INTEGER PRIMARY KEY, params TEXT NOT NULL);";
  sqlite3_exec(db, sql, NULL, NULL, NULL);
  const char *sql2 = "CREATE TABLE IF NOT EXISTS logs (ts INTEGER, src_ip TEXT, dst_ip TEXT, protocol INTEGER, bps INTEGER, len INTEGER, status TEXT, block_time INTEGER);";
  sqlite3_exec(db, sql2, NULL, NULL, NULL);
}

// Load rules from DB and apply them
static void load_rules(void) {
  sqlite3_stmt *st;
  if (sqlite3_prepare_v2(db, "SELECT idx, params FROM filters ORDER BY idx", -1, &st, NULL) == SQLITE_OK) {
    while (sqlite3_step(st) == SQLITE_ROW) {
      int idx = sqlite3_column_int(st, 0);
      const unsigned char *j = sqlite3_column_text(st, 1);
      apply_filter(idx, (const char *) j);
    }
    sqlite3_finalize(st);
  }
}

// Helpers to send JSON reply
static void json_reply(struct mg_connection *c, int code, const char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  mg_http_reply(c, code, "Content-Type: application/json\r\n", fmt, ap);
  va_end(ap);
}

static int check_auth(struct mg_http_message *hm) {
  struct mg_str *hdr = mg_http_get_header(hm, "Authorization");
  if (hdr == NULL) return 0;
  const char prefix[] = "Bearer ";
  if (hdr->len <= strlen(prefix) || strncmp(hdr->buf, prefix, strlen(prefix)) != 0)
    return 0;
  const char *tok = AUTH_TOKEN;
  size_t tok_len = strlen(tok);
  if (hdr->len - strlen(prefix) != tok_len) return 0;
  return strncmp(hdr->buf + strlen(prefix), tok, tok_len) == 0;
}

// HTTP request handler
static int method_is(struct mg_str m, const char *s) {
  return mg_strcasecmp(m, mg_str(s)) == 0;
}

static bool match_uri(struct mg_http_message *hm, const char *pat) {
  return mg_match(hm->uri, mg_str(pat), NULL);
}

static void handle(struct mg_connection *c, int ev, void *ev_data) {
  if (ev == MG_EV_HTTP_MSG) {
    struct mg_http_message *hm = (struct mg_http_message *) ev_data;
    if (!check_auth(hm)) {
      json_reply(c, 401, "{\"error\":\"unauthorized\"}");
      return;
    }
    if (match_uri(hm, "/filters")) {
      if (method_is(hm->method, "POST")) {
        int idx = 0; sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT IFNULL(MAX(idx),0)+1 FROM filters", -1, &st, NULL);
        if (sqlite3_step(st) == SQLITE_ROW) idx = sqlite3_column_int(st, 0);
        sqlite3_finalize(st);
        char body[512]; memcpy(body, hm->body.buf, hm->body.len); body[hm->body.len] = '\0';
        if (apply_filter(idx, body) != 0) {
          json_reply(c, 400, "{\"error\":\"failed\"}");
        } else {
          sqlite3_stmt *ins;
          sqlite3_prepare_v2(db, "INSERT INTO filters(idx, params) VALUES(?,?)", -1, &ins, NULL);
          sqlite3_bind_int(ins, 1, idx);
          sqlite3_bind_text(ins, 2, body, -1, SQLITE_TRANSIENT);
          sqlite3_step(ins); sqlite3_finalize(ins);
          json_reply(c, 201, "{\"result\":\"ok\",\"idx\":%d}", idx);
        }
      } else if (method_is(hm->method, "GET")) {
        char buf[4096];
        size_t off = 0;
        off += snprintf(buf + off, sizeof(buf) - off, "[");
        sqlite3_stmt *st;
        int first = 1;
        if (sqlite3_prepare_v2(db, "SELECT idx, params FROM filters ORDER BY idx", -1, &st, NULL) == SQLITE_OK) {
          while (sqlite3_step(st) == SQLITE_ROW) {
            if (!first) off += snprintf(buf + off, sizeof(buf) - off, ",");
            first = 0;
            int idx = sqlite3_column_int(st, 0);
            const unsigned char *p = sqlite3_column_text(st, 1);
            off += snprintf(buf + off, sizeof(buf) - off, "{\"idx\":%d,\"params\":%s}", idx, p);
          }
          sqlite3_finalize(st);
        }
        off += snprintf(buf + off, sizeof(buf) - off, "]");
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", buf);
      } else {
        mg_http_reply(c, 405, "", "");
      }

    } else if (match_uri(hm, "/stats")) {
      if (method_is(hm->method, "GET")) {
        char buf[8192];
        size_t off = 0;
        off += snprintf(buf + off, sizeof(buf) - off, "[");
        sqlite3_stmt *st;
        int first = 1;
        if (sqlite3_prepare_v2(db, "SELECT ts, src_ip, dst_ip, protocol, bps, len, status, block_time FROM logs ORDER BY ts DESC LIMIT 100", -1, &st, NULL) == SQLITE_OK) {
          while (sqlite3_step(st) == SQLITE_ROW) {
            if (!first) off += snprintf(buf + off, sizeof(buf) - off, ",");
            first = 0;
            off += snprintf(buf + off, sizeof(buf) - off,
              "{\"ts\":%lld,\"src_ip\":\"%s\",\"dst_ip\":\"%s\",\"protocol\":%d,\"bps\":%lld,\"length\":%d,\"status\":\"%s\",\"block_time\":%d}",
              sqlite3_column_int64(st,0), sqlite3_column_text(st,1), sqlite3_column_text(st,2), sqlite3_column_int(st,3), sqlite3_column_int64(st,4), sqlite3_column_int(st,5), sqlite3_column_text(st,6), sqlite3_column_int(st,7));
          }
          sqlite3_finalize(st);
        }
        off += snprintf(buf + off, sizeof(buf) - off, "]");
        mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", buf);
      } else {
        mg_http_reply(c, 405, "", "");
      }
    } else if (match_uri(hm, "/filters/#")) {
      int idx = atoi(&hm->uri.buf[9]);
      if (method_is(hm->method, "GET")) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT params FROM filters WHERE idx=?", -1, &st, NULL);
        sqlite3_bind_int(st, 1, idx);
        if (sqlite3_step(st) == SQLITE_ROW) {
          const unsigned char *p = sqlite3_column_text(st, 0);
          char buf[512];
          snprintf(buf, sizeof(buf), "{\"idx\":%d,\"params\":%s}", idx, p);
          mg_http_reply(c, 200, "Content-Type: application/json\r\n", "%s", buf);
        } else {
          json_reply(c, 404, "{\"error\":\"not found\"}");
        }
        sqlite3_finalize(st);
      } else if (method_is(hm->method, "PATCH")) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT idx FROM filters WHERE idx=?", -1, &st, NULL);
        sqlite3_bind_int(st, 1, idx);
        int exists = sqlite3_step(st) == SQLITE_ROW; sqlite3_finalize(st);
        if (!exists) { json_reply(c, 404, "{\"error\":\"not found\"}"); return; }
        char body[512]; memcpy(body, hm->body.buf, hm->body.len); body[hm->body.len] = '\0';
        if (apply_filter(idx, body) != 0) {
          json_reply(c, 400, "{\"error\":\"failed\"}");
        } else {
          sqlite3_stmt *up;
          sqlite3_prepare_v2(db, "UPDATE filters SET params=? WHERE idx=?", -1, &up, NULL);
          sqlite3_bind_text(up, 1, body, -1, SQLITE_TRANSIENT);
          sqlite3_bind_int(up, 2, idx);
          sqlite3_step(up); sqlite3_finalize(up);
          json_reply(c, 200, "{\"result\":\"ok\",\"idx\":%d}", idx);
        }
      } else if (method_is(hm->method, "DELETE")) {
        sqlite3_stmt *st;
        sqlite3_prepare_v2(db, "SELECT idx FROM filters WHERE idx=?", -1, &st, NULL);
        sqlite3_bind_int(st, 1, idx);
        int exists = sqlite3_step(st) == SQLITE_ROW; sqlite3_finalize(st);
        if (!exists) { json_reply(c, 404, "{\"error\":\"not found\"}"); return; }
        if (remove_filter(idx) != 0) {
          json_reply(c, 400, "{\"error\":\"failed\"}");
        } else {
          sqlite3_stmt *del;
          sqlite3_prepare_v2(db, "DELETE FROM filters WHERE idx=?", -1, &del, NULL);
          sqlite3_bind_int(del, 1, idx); sqlite3_step(del); sqlite3_finalize(del);
          json_reply(c, 200, "{\"result\":\"ok\",\"idx\":%d}", idx);
        }
      } else {
        mg_http_reply(c, 405, "", "");
      }
    } else {
      json_reply(c, 404, "{\"error\":\"not found\"}");
    }
  }
}

int main(void) {
  struct mg_mgr mgr;
  mg_mgr_init(&mgr);
  const char *env_tok = getenv("XDPFW_API_TOKEN");
  if (env_tok && *env_tok) AUTH_TOKEN = env_tok;
  init_db();
  load_rules();
  mg_http_listen(&mgr, "http://0.0.0.0:8080", handle, NULL);
  for (;;) mg_mgr_poll(&mgr, 1000);
  mg_mgr_free(&mgr);
  sqlite3_close(db);
  return 0;
}

