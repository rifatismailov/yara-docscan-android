// JNI bridge between the Android app and libyara + the docscan module.
//
// This is the Android counterpart of the docscan parts of cli/yara.c
// (--docscan-json, Layer-2 re-scan of the VBA and parts, --file-vars):
// the same JSON object per file, built into a string instead of stdout.
// Keep it in sync with cli/yara.c until that logic moves into libyara.

#include <ctype.h>
#include <jni.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <android/log.h>
#include <yara.h>
#include <yara/docscan_disarm.h>

#define TAG "docscan-jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static const char* file_vars_names[] = {
    "filename", "filepath", "extension", "filetype", "owner", NULL};

// ---------------------------------------------------------------- strbuf --

typedef struct
{
  char* s;
  size_t len;
  size_t cap;
  int oom;
} strbuf;

static void sb_grow(strbuf* b, size_t need)
{
  if (b->oom || b->len + need + 1 <= b->cap)
    return;
  size_t cap = b->cap ? b->cap : 1024;
  while (cap < b->len + need + 1) cap *= 2;
  char* n = (char*) realloc(b->s, cap);
  if (n == NULL) { b->oom = 1; return; }
  b->s = n;
  b->cap = cap;
}

static void sb_putn(strbuf* b, const char* s, size_t n)
{
  sb_grow(b, n);
  if (b->oom) return;
  memcpy(b->s + b->len, s, n);
  b->len += n;
  b->s[b->len] = '\0';
}

static void sb_puts(strbuf* b, const char* s) { sb_putn(b, s, strlen(s)); }

static void sb_printf(strbuf* b, const char* fmt, ...)
{
  char tmp[1024];
  va_list ap;
  va_start(ap, fmt);
  int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);
  if (n < 0) return;
  if ((size_t) n < sizeof(tmp)) { sb_putn(b, tmp, (size_t) n); return; }
  char* big = (char*) malloc((size_t) n + 1);
  if (big == NULL) { b->oom = 1; return; }
  va_start(ap, fmt);
  vsnprintf(big, (size_t) n + 1, fmt, ap);
  va_end(ap);
  sb_putn(b, big, (size_t) n);
  free(big);
}

// JSON string body (no quotes), same escaping as docscan_json_puts in cli/yara.c.
static void sb_json(strbuf* b, const char* s)
{
  for (const unsigned char* p = (const unsigned char*) s; *p; p++)
  {
    switch (*p)
    {
    case '"': sb_puts(b, "\\\""); break;
    case '\\': sb_puts(b, "\\\\"); break;
    case '\n': sb_puts(b, "\\n"); break;
    case '\r': sb_puts(b, "\\r"); break;
    case '\t': sb_puts(b, "\\t"); break;
    default:
      if (*p < 0x20) sb_printf(b, "\\u%04x", *p);
      else sb_putn(b, (const char*) p, 1);
    }
  }
}

// ---------------------------------------------- docscan state (cli/yara.c) --

struct ds_part
{
  char name[256];
  uint8_t* data;
  size_t len;
};

typedef struct
{
  int active;
  const char* ftype;
  char template_url[512];
  char dde_command[512];
  char vba_evidence[512];
  char lnk_target[512];
  char lnk_args[512];
  char archive_docs[1024];
  char* vba;
  struct ds_part* parts;
  int n_parts;
  size_t vba_len;
  int max_severity;  // 0 INFO, 1 MEDIUM, 2 HIGH
  char findings[2048];
  char details[8192];
  char file_matches[4096];
  char info_matches[4096];
  char doc_matches[4096];
  char findings_text[4096];
  char descriptions[8192];
  docscan_disarm_info ds;
} DOCSCAN_STATE;

static void docscan_defang(char* s)
{
  for (char* p = s; *p; p++)
  {
    if (strncmp(p, "http", 4) == 0) memcpy(p, "hxxp", 4);
    else if (strncmp(p, "ftp", 3) == 0) memcpy(p, "fxp", 3);
  }
}

static void docscan_list_add(char* list, size_t sz, const char* token)
{
  size_t l = strlen(list);
  char esc[512];
  size_t k = 0;
  for (const char* p = token; *p && k + 2 < sizeof(esc); p++)
  {
    if (*p == '"' || *p == '\\') esc[k++] = '\\';
    esc[k++] = *p;
  }
  esc[k] = '\0';
  if (l + strlen(esc) + 4 < sz)
    snprintf(list + l, sz - l, "%s\"%s\"", l ? "," : "", esc);
}

static void docscan_obj_add(char* obj, size_t sz, const char* key, const char* val)
{
  char k[256], v[512];
  size_t a = 0, b = 0;
  for (const char* p = key; *p && a + 2 < sizeof(k); p++)
  {
    if (*p == '"' || *p == '\\') k[a++] = '\\';
    k[a++] = *p;
  }
  k[a] = '\0';
  for (const char* p = val; *p && b + 2 < sizeof(v); p++)
  {
    unsigned char c = (unsigned char) *p;
    if (c < 0x20) { v[b++] = ' '; continue; }
    if (c == '"' || c == '\\') v[b++] = '\\';
    v[b++] = (char) c;
  }
  v[b] = '\0';
  size_t l = strlen(obj);
  if (l + a + b + 8 < sz)
    snprintf(obj + l, sz - l, "%s{\"rule\":\"%s\",\"description\":\"%s\"}", l ? "," : "", k, v);
}

static int docscan_list_has(const char* list, const char* token)
{
  char q[512];
  snprintf(q, sizeof(q), "\"%s\"", token);
  return strstr(list, q) != NULL;
}

static void docscan_state_free(DOCSCAN_STATE* st)
{
  for (int i = 0; i < st->n_parts; i++) free(st->parts[i].data);
  free(st->parts);
  free(st->vba);
  memset(st, 0, sizeof(*st));
}

// field is always a literal name; do NOT pass it as ("%s", field): libyara expands %s / %i only inside
// [...] (array index / dict key). Hence the macro, which keeps the format a string literal.
#define docscan_copy_string(m, field, out, sz) docscan_copy_sized(yr_object_get_string(m, field), out, sz)

static void docscan_copy_sized(SIZED_STRING* s, char* out, size_t sz)
{
  size_t n = (s == NULL) ? 0 : (size_t) s->length;
  if (n >= sz) n = sz - 1;
  if (n) memcpy(out, s->c_string, n);
  out[n] = '\0';
}

static void docscan_capture(YR_OBJECT* m, DOCSCAN_STATE* st)
{
  docscan_state_free(st);
  st->active = 1;
  st->ds.present = 1;
  st->ftype = "unknown";
  if (yr_object_get_integer(m, "is_archive") == 1) { st->ftype = "zip"; st->ds.type = 6; }
  else if (yr_object_get_integer(m, "is_ooxml") == 1) { st->ftype = "ooxml"; st->ds.type = 1; }
  else if (yr_object_get_integer(m, "is_ole") == 1) { st->ftype = "ole"; st->ds.type = 2; }
  else if (yr_object_get_integer(m, "is_rtf") == 1) { st->ftype = "rtf"; st->ds.type = 3; }
  else if (yr_object_get_integer(m, "is_pdf") == 1) { st->ftype = "pdf"; st->ds.type = 4; }
  else if (yr_object_get_integer(m, "is_lnk") == 1) { st->ftype = "lnk"; st->ds.type = 5; }

  docscan_copy_string(m, "template_url", st->template_url, sizeof(st->template_url));
  docscan_copy_string(m, "archive_docs", st->archive_docs, sizeof(st->archive_docs));
  docscan_copy_string(m, "dde_command", st->dde_command, sizeof(st->dde_command));
  docscan_copy_string(m, "vba_evidence", st->vba_evidence, sizeof(st->vba_evidence));
  docscan_copy_string(m, "lnk_target", st->lnk_target, sizeof(st->lnk_target));
  docscan_copy_string(m, "lnk_args", st->lnk_args, sizeof(st->lnk_args));

  int np = (int) yr_object_get_integer(m, "number_of_parts");
  if (np > 0 && np <= 1024)
  {
    st->parts = (struct ds_part*) calloc((size_t) np, sizeof(struct ds_part));
    for (int i = 0; st->parts != NULL && i < np; i++)
    {
      SIZED_STRING* nm = yr_object_get_string(m, "parts[%i].name", i);
      SIZED_STRING* dt = yr_object_get_string(m, "parts[%i].data", i);
      if (dt == NULL || dt->length == 0) continue;
      struct ds_part* p = &st->parts[st->n_parts];
      p->data = (uint8_t*) malloc((size_t) dt->length);
      if (p->data == NULL) continue;
      memcpy(p->data, dt->c_string, (size_t) dt->length);
      p->len = (size_t) dt->length;
      snprintf(p->name, sizeof(p->name), "%s", nm ? nm->c_string : "");
      st->n_parts++;
    }
  }

  SIZED_STRING* vba = yr_object_get_string(m, "vba_code");
  if (vba != NULL && vba->length > 0)
  {
    st->vba = (char*) malloc((size_t) vba->length);
    if (st->vba != NULL)
    {
      memcpy(st->vba, vba->c_string, (size_t) vba->length);
      st->vba_len = (size_t) vba->length;
    }
  }
}

static const char* docscan_meta(YR_RULE* rule, const char* name)
{
  YR_META* meta;
  yr_rule_metas_foreach(rule, meta)
  {
    if (meta->type == META_TYPE_STRING && strcmp(meta->identifier, name) == 0)
      return meta->string;
  }
  return NULL;
}

static int docscan_has_tag(YR_RULE* rule, const char* want)
{
  const char* tag;
  yr_rule_tags_foreach(rule, tag)
  {
    if (strcmp(tag, want) == 0) return 1;
  }
  return 0;
}

static int docscan_is_info(YR_RULE* rule) { return docscan_has_tag(rule, "docscan_info"); }

static void docscan_on_match(YR_RULE* rule, DOCSCAN_STATE* st)
{
  const char* sev = docscan_meta(rule, "severity");

  if (sev == NULL)
  {
    if (docscan_is_info(rule))
    {
      docscan_list_add(st->info_matches, sizeof(st->info_matches), rule->identifier);
      return;
    }
    if (docscan_has_tag(rule, "docscan_doc"))
      docscan_list_add(st->doc_matches, sizeof(st->doc_matches), rule->identifier);
    else
      docscan_list_add(st->file_matches, sizeof(st->file_matches), rule->identifier);
    const char* desc = docscan_meta(rule, "description");
    if (desc == NULL) desc = docscan_meta(rule, "Description");
    if (desc != NULL)
      docscan_obj_add(st->descriptions, sizeof(st->descriptions), rule->identifier, desc);
    return;
  }

  int level = 0;
  if (strcmp(sev, "HIGH") == 0 || strcmp(sev, "high") == 0) level = 2;
  else if (strcmp(sev, "MEDIUM") == 0 || strcmp(sev, "medium") == 0) level = 1;
  if (level > st->max_severity) st->max_severity = level;

  const char* finding = docscan_meta(rule, "finding");
  if (finding == NULL) finding = rule->identifier;
  if (!docscan_list_has(st->findings, finding))
  {
    docscan_list_add(st->findings, sizeof(st->findings), finding);
    const char* text = docscan_meta(rule, "text");
    if (text != NULL) docscan_list_add(st->findings_text, sizeof(st->findings_text), text);
  }

  const char* disarm = docscan_meta(rule, "disarm");
  const char* mitre = docscan_meta(rule, "mitre");

  char obj[1024], tok[512];
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), rule->identifier);
  snprintf(obj, sizeof(obj), "{\"rule\":%s", tok);
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), finding);
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"finding\":%s", tok);
  tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), level == 2 ? "HIGH" : level == 1 ? "MEDIUM" : "INFO");
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"severity\":%s", tok);
  if (disarm != NULL)
  {
    tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), disarm);
    snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"disarm\":%s", tok);
  }
  if (mitre != NULL)
  {
    tok[0] = '\0'; docscan_list_add(tok, sizeof(tok), mitre);
    snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), ",\"mitre\":%s", tok);
  }
  snprintf(obj + strlen(obj), sizeof(obj) - strlen(obj), "}");
  size_t l = strlen(st->details);
  if (l + strlen(obj) + 2 < sizeof(st->details))
    snprintf(st->details + l, sizeof(st->details) - l, "%s%s", l ? "," : "", obj);

  if (disarm != NULL)
  {
    docscan_disarm_info* ds = &st->ds;
    if (strcmp(disarm, "macro") == 0) ds->macro = 1;
    else if (strcmp(disarm, "remote_template") == 0) ds->remote_template = 1;
    else if (strcmp(disarm, "protocol_handler") == 0) ds->protocol_handler = 1;
    else if (strcmp(disarm, "dde") == 0) ds->dde_auto = 1;
    else if (strcmp(disarm, "embedded") == 0) ds->embedded = 1;
    else if (strcmp(disarm, "rtf_objupdate") == 0) ds->rtf_objupdate = 1;
    else if (strcmp(disarm, "lnk_delete") == 0) ds->lnk_bad = 1;
    else if (strcmp(disarm, "quarantine") == 0) ds->quarantine = 1;
    else return;
    ds->high = 1;
  }
}

typedef struct
{
  char* buf;
  size_t sz;
  char* desc;
  size_t desc_sz;
} vmatch_collect;

static int vendor_match_cb(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    YR_RULE* r = (YR_RULE*) message_data;
    if (r->identifier && docscan_meta(r, "severity") == NULL && !docscan_is_info(r))
    {
      vmatch_collect* v = (vmatch_collect*) user_data;
      docscan_list_add(v->buf, v->sz, r->identifier);
      char needle[300];
      snprintf(needle, sizeof(needle), "\"rule\":\"%s\"", r->identifier);
      if (v->desc != NULL && !strstr(v->desc, needle))
      {
        const char* d = docscan_meta(r, "description");
        if (d == NULL) d = docscan_meta(r, "Description");
        if (d != NULL) docscan_obj_add(v->desc, v->desc_sz, r->identifier, d);
      }
    }
  }
  return CALLBACK_CONTINUE;
}

static void json_evidence(strbuf* b, const char* field, const char* value, int defang, int* first)
{
  if (value == NULL || value[0] == '\0') return;
  char buf[1024];
  snprintf(buf, sizeof(buf), "%s", value);
  if (defang) docscan_defang(buf);
  sb_printf(b, "%s\"%s\":\"", *first ? "" : ",", field);
  sb_json(b, buf);
  sb_puts(b, "\"");
  *first = 0;
}

// The same object print_docscan_json() prints, plus "disarm_plan" for the app.
static void build_docscan_json(YR_RULES* rules, DOCSCAN_STATE* st, strbuf* b)
{
  const char* verdict = st->max_severity == 2 ? "HIGH" : st->max_severity == 1 ? "MEDIUM" : "INFO";

  sb_printf(b, "{\"ftype\":\"%s\",\"findings\":[%s],\"verdict\":\"%s\",\"evidence\":{",
            st->ftype, st->findings, verdict);
  int fe = 1;
  json_evidence(b, "template_url", st->template_url, 1, &fe);
  json_evidence(b, "dde_command", st->dde_command, 1, &fe);
  json_evidence(b, "vba_evidence", st->vba_evidence, 0, &fe);
  json_evidence(b, "lnk_target", st->lnk_target, 0, &fe);
  json_evidence(b, "lnk_args", st->lnk_args, 1, &fe);
  json_evidence(b, "archive_docs", st->archive_docs, 0, &fe);
  sb_puts(b, "}");

  // Layer 2: the decompressed VBA.
  char vmatches[4096] = "";
  if (st->vba != NULL && st->vba_len > 0)
  {
    YR_SCANNER* sc2 = NULL;
    if (yr_scanner_create(rules, &sc2) == ERROR_SUCCESS)
    {
      vmatch_collect vm = {vmatches, sizeof(vmatches), st->descriptions, sizeof(st->descriptions)};
      yr_scanner_set_callback(sc2, vendor_match_cb, &vm);
      yr_scanner_scan_mem(sc2, (const uint8_t*) st->vba, st->vba_len);
      yr_scanner_destroy(sc2);
    }
  }

  // Layer 2: every decompressed part of the document.
  strbuf pm = {0};
  if (st->n_parts > 0)
  {
    YR_SCANNER* sc3 = NULL;
    if (yr_scanner_create(rules, &sc3) == ERROR_SUCCESS)
    {
      for (int i = 0; i < st->n_parts; i++)
      {
        char found[2048] = "";
        vmatch_collect c = {found, sizeof(found), st->descriptions, sizeof(st->descriptions)};
        yr_scanner_set_callback(sc3, vendor_match_cb, &c);
        yr_scanner_scan_mem(sc3, st->parts[i].data, st->parts[i].len);
        if (found[0] == '\0') continue;
        char pname[600] = "";
        docscan_list_add(pname, sizeof(pname), st->parts[i].name);
        sb_printf(&pm, "%s{\"part\":%s,\"rules\":[%s]}", pm.len ? "," : "", pname, found);
      }
      yr_scanner_destroy(sc3);
    }
  }

  sb_printf(b, ",\"yara_matches\":[%s]", vmatches);
  sb_printf(b, ",\"yara_part_matches\":[%s]", pm.s ? pm.s : "");
  free(pm.s);
  sb_printf(b, ",\"yara_file_matches\":[%s]", st->file_matches);
  sb_printf(b, ",\"yara_doc_matches\":[%s]", st->doc_matches);
  sb_printf(b, ",\"yara_info_matches\":[%s]", st->info_matches);
  sb_printf(b, ",\"findings_text\":[%s]", st->findings_text);
  sb_printf(b, ",\"yara_descriptions\":[%s]", st->descriptions);
  sb_printf(b, ",\"details\":[%s]", st->details);

  const docscan_disarm_info* d = &st->ds;
  sb_printf(b,
            ",\"disarm_plan\":{\"needed\":%s,\"macro\":%d,\"remote_template\":%d,"
            "\"protocol_handler\":%d,\"dde\":%d,\"embedded\":%d,\"rtf_objupdate\":%d,"
            "\"lnk_delete\":%d,\"quarantine\":%d}",
            d->high ? "true" : "false", d->macro, d->remote_template, d->protocol_handler,
            d->dde_auto, d->embedded, d->rtf_objupdate, d->lnk_bad, d->quarantine);
  sb_puts(b, "}");
}

// ------------------------------------------------------------- file vars --

static const char* file_vars_type(const uint8_t* h, size_t n, const char* ext)
{
  if (n >= 2 && h[0] == 'M' && h[1] == 'Z') return "EXE";
  if (n >= 4 && memcmp(h, "\x7f" "ELF", 4) == 0) return "ELF";
  if (n >= 4 && (memcmp(h, "\xfe\xed\xfa\xce", 4) == 0 || memcmp(h, "\xfe\xed\xfa\xcf", 4) == 0 ||
                 memcmp(h, "\xce\xfa\xed\xfe", 4) == 0 || memcmp(h, "\xcf\xfa\xed\xfe", 4) == 0))
    return "MACH-O";
  if (n >= 4 && memcmp(h, "MDMP", 4) == 0) return "MDMP";
  if (n >= 4 && memcmp(h, "PK\x03\x04", 4) == 0) return "ZIP";
  if (n >= 4 && memcmp(h, "Rar!", 4) == 0) return "RAR";
  if (n >= 4 && memcmp(h, "7z\xbc\xaf", 4) == 0) return "7Z";
  if (n >= 5 && memcmp(h, "{\\rtf", 5) == 0) return "RTF";
  if (n >= 4 && memcmp(h, "%PDF", 4) == 0) return "PDF";
  if (n >= 8 && memcmp(h, "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 8) == 0) return "OLE";
  static const char* by_ext[][2] = {
      {".vbs", "VBS"}, {".vbe", "VBS"}, {".bat", "BATCH"}, {".cmd", "BATCH"},
      {".ps1", "PowerShell"}, {".psm1", "PowerShell"}, {".py", "Python"}, {".php", "PHP"},
      {".jsp", "JSP"}, {".asp", "ASP"}, {".aspx", "ASP"}, {".js", "JS"}, {".hta", "HTA"},
      {NULL, NULL}};
  for (int i = 0; by_ext[i][0] != NULL; i++)
    if (strcmp(ext, by_ext[i][0]) == 0) return by_ext[i][1];
  return "";
}

// name: display name of the document (content URIs have no real path); dir: its folder or "".
static void file_vars_set(YR_SCANNER* scanner, const char* name, const char* dir, int fd)
{
  char ext[64] = "";
  const char* dot = strrchr(name, '.');
  if (dot && dot != name && strlen(dot) < sizeof(ext))
    for (size_t i = 0; (ext[i] = (char) tolower((unsigned char) dot[i])); i++)
      ;
  uint8_t h[16];
  ssize_t n = pread(fd, h, sizeof(h), 0);
  if (n < 0) n = 0;
  yr_scanner_define_string_variable(scanner, "filename", name);
  yr_scanner_define_string_variable(scanner, "filepath", dir);
  yr_scanner_define_string_variable(scanner, "extension", ext);
  yr_scanner_define_string_variable(scanner, "filetype", file_vars_type(h, (size_t) n, ext));
  yr_scanner_define_string_variable(scanner, "owner", "");
}

// ------------------------------------------------------------------- JNI --

typedef struct
{
  DOCSCAN_STATE dsc;
} SCAN_ARGS;

static int scan_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  SCAN_ARGS* a = (SCAN_ARGS*) user_data;
  switch (message)
  {
  case CALLBACK_MSG_RULE_MATCHING:
    if (a->dsc.active) docscan_on_match((YR_RULE*) message_data, &a->dsc);
    return CALLBACK_CONTINUE;
  case CALLBACK_MSG_MODULE_IMPORTED:
  {
    YR_OBJECT* object = (YR_OBJECT*) message_data;
    if (object->identifier != NULL && strcmp(object->identifier, "docscan") == 0)
      docscan_capture(object, &a->dsc);
    return CALLBACK_CONTINUE;
  }
  default:
    return CALLBACK_CONTINUE;
  }
}

static void throw_ex(JNIEnv* env, const char* msg)
{
  jclass c = (*env)->FindClass(env, "yara/docscan/android/scan/DocScanException");
  if (c != NULL) (*env)->ThrowNew(env, c, msg);
}

JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved)
{
  if (yr_initialize() != ERROR_SUCCESS)
  {
    LOGE("yr_initialize failed");
    return JNI_ERR;
  }
  return JNI_VERSION_1_6;
}

typedef struct
{
  strbuf errors;
  int count;
} COMPILE_ERRORS;

static void compiler_cb(int level, const char* file, int line, const YR_RULE* rule, const char* msg,
                        void* user)
{
  if (level != YARA_ERROR_LEVEL_ERROR) return;
  COMPILE_ERRORS* e = (COMPILE_ERRORS*) user;
  if (e->count++ < 20)
    sb_printf(&e->errors, "%s(%d): %s\n", file ? file : "?", line, msg);
}

// Compiles the index file (includes are resolved relative to it); returns a YR_RULES* handle.
JNIEXPORT jlong JNICALL
Java_yara_docscan_android_scan_NativeYara_compile(JNIEnv* env, jclass cls, jstring jpath)
{
  const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
  YR_COMPILER* compiler = NULL;
  YR_RULES* rules = NULL;
  COMPILE_ERRORS errs = {0};

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
  {
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    throw_ex(env, "yr_compiler_create failed");
    return 0;
  }
  yr_compiler_set_callback(compiler, compiler_cb, &errs);
  for (int i = 0; file_vars_names[i] != NULL; i++)
    yr_compiler_define_string_variable(compiler, file_vars_names[i], "");

  FILE* fh = fopen(path, "r");
  if (fh == NULL)
  {
    sb_printf(&errs.errors, "cannot open %s", path);
    errs.count = 1;
  }
  else
  {
    yr_compiler_add_file(compiler, fh, NULL, path);
    fclose(fh);
  }
  (*env)->ReleaseStringUTFChars(env, jpath, path);

  if (errs.count == 0 && yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
  {
    sb_puts(&errs.errors, "yr_compiler_get_rules failed");
    errs.count = 1;
  }
  yr_compiler_destroy(compiler);

  if (errs.count > 0)
  {
    throw_ex(env, errs.errors.s ? errs.errors.s : "compile error");
    free(errs.errors.s);
    return 0;
  }
  free(errs.errors.s);
  return (jlong) (intptr_t) rules;
}

JNIEXPORT jboolean JNICALL
Java_yara_docscan_android_scan_NativeYara_save(JNIEnv* env, jclass cls, jlong h, jstring jpath)
{
  const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
  int r = yr_rules_save((YR_RULES*) (intptr_t) h, path);
  (*env)->ReleaseStringUTFChars(env, jpath, path);
  return r == ERROR_SUCCESS;
}

// Loads rules saved with save(); returns 0 when the file is missing or incompatible.
JNIEXPORT jlong JNICALL
Java_yara_docscan_android_scan_NativeYara_load(JNIEnv* env, jclass cls, jstring jpath)
{
  const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
  YR_RULES* rules = NULL;
  int r = yr_rules_load(path, &rules);
  (*env)->ReleaseStringUTFChars(env, jpath, path);
  return r == ERROR_SUCCESS ? (jlong) (intptr_t) rules : 0;
}

JNIEXPORT void JNICALL
Java_yara_docscan_android_scan_NativeYara_destroy(JNIEnv* env, jclass cls, jlong h)
{
  if (h != 0) yr_rules_destroy((YR_RULES*) (intptr_t) h);
}

JNIEXPORT jstring JNICALL
Java_yara_docscan_android_scan_NativeYara_version(JNIEnv* env, jclass cls)
{
  return (*env)->NewStringUTF(env, YR_VERSION);
}

// Scans an open file descriptor (the caller keeps ownership) -> the docscan JSON object as UTF-8
// bytes (document strings may hold invalid UTF-8, which NewStringUTF would reject).
JNIEXPORT jbyteArray JNICALL
Java_yara_docscan_android_scan_NativeYara_scanFd(
    JNIEnv* env, jclass cls, jlong h, jint fd, jstring jname, jstring jdir, jint timeout)
{
  YR_RULES* rules = (YR_RULES*) (intptr_t) h;
  if (rules == NULL) { throw_ex(env, "rules are not loaded"); return NULL; }

  YR_SCANNER* scanner = NULL;
  if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS)
  {
    throw_ex(env, "yr_scanner_create failed");
    return NULL;
  }

  SCAN_ARGS* args = (SCAN_ARGS*) calloc(1, sizeof(SCAN_ARGS));  // ~50 KB: keep it off the stack
  if (args == NULL) { yr_scanner_destroy(scanner); throw_ex(env, "out of memory"); return NULL; }

  const char* name = (*env)->GetStringUTFChars(env, jname, NULL);
  const char* dir = (*env)->GetStringUTFChars(env, jdir, NULL);
  file_vars_set(scanner, name, dir, fd);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  (*env)->ReleaseStringUTFChars(env, jdir, dir);

  yr_scanner_set_callback(scanner, scan_callback, args);
  if (timeout > 0) yr_scanner_set_timeout(scanner, timeout);

  int r = yr_scanner_scan_fd(scanner, fd);
  yr_scanner_destroy(scanner);

  strbuf out = {0};
  if (r != ERROR_SUCCESS && r != ERROR_SCAN_TIMEOUT)
    sb_printf(&out, "{\"error\":\"scan failed\",\"code\":%d}", r);
  else if (!args->dsc.active)
    sb_puts(&out, "{\"error\":\"docscan module did not run\"}");
  else
  {
    build_docscan_json(rules, &args->dsc, &out);
    if (r == ERROR_SCAN_TIMEOUT && out.len > 0)
    {
      out.len--;  // drop the closing brace, add the flag
      out.s[out.len] = '\0';
      sb_puts(&out, ",\"timeout\":true}");
    }
  }
  docscan_state_free(&args->dsc);
  free(args);

  if (out.oom || out.s == NULL)
  {
    free(out.s);
    throw_ex(env, "out of memory");
    return NULL;
  }
  jbyteArray arr = (*env)->NewByteArray(env, (jsize) out.len);
  if (arr != NULL) (*env)->SetByteArrayRegion(env, arr, 0, (jsize) out.len, (const jbyte*) out.s);
  free(out.s);
  return arr;
}
