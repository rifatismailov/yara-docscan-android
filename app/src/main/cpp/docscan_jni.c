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
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android/log.h>
#include <yara.h>
#include <yara/docscan_critical.h>
#include <yara/docscan_disarm.h>
#include <time.h>

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
  char archive_entries[4096];  // JSON tokens: names of the first-level files of a plain ZIP (Android: APK in a zip)
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

  int na = (int) yr_object_get_integer(m, "number_of_archive_entries");
  for (int i = 0; i < na && i < 1024; i++)
  {
    SIZED_STRING* nm = yr_object_get_string(m, "archive_entries[%i].name", i);
    if (nm != NULL && nm->length > 0)
      docscan_list_add(st->archive_entries, sizeof(st->archive_entries), nm->c_string);
  }

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
  sb_printf(b, ",\"archive_entries\":[%s]", st->archive_entries);

  const docscan_disarm_info* d = &st->ds;
  sb_printf(b,
            ",\"disarm_plan\":{\"needed\":%s,\"type\":%d,\"macro\":%d,\"remote_template\":%d,"
            "\"protocol_handler\":%d,\"dde\":%d,\"embedded\":%d,\"rtf_objupdate\":%d,"
            "\"lnk_delete\":%d,\"quarantine\":%d}",
            d->high ? "true" : "false", d->type, d->macro, d->remote_template, d->protocol_handler,
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
static void file_vars_set(YR_SCANNER* scanner, const char* name, const char* dir, const uint8_t* h, size_t n)
{
  char ext[64] = "";
  const char* dot = strrchr(name, '.');
  if (dot && dot != name && strlen(dot) < sizeof(ext))
    for (size_t i = 0; (ext[i] = (char) tolower((unsigned char) dot[i])); i++)
      ;
  yr_scanner_define_string_variable(scanner, "filename", name);
  yr_scanner_define_string_variable(scanner, "filepath", dir);
  yr_scanner_define_string_variable(scanner, "extension", ext);
  yr_scanner_define_string_variable(scanner, "filetype", file_vars_type(h, n < 16 ? n : 16, ext));
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

static jbyteArray to_bytes(JNIEnv* env, strbuf* out)
{
  if (out->oom || out->s == NULL)
  {
    free(out->s);
    throw_ex(env, "out of memory");
    return NULL;
  }
  jbyteArray arr = (*env)->NewByteArray(env, (jsize) out->len);
  if (arr != NULL) (*env)->SetByteArrayRegion(env, arr, 0, (jsize) out->len, (const jbyte*) out->s);
  free(out->s);
  return arr;
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

static size_t fd_stream_read(void* ptr, size_t size, size_t count, void* user_data)
{
  int fd = (int) (intptr_t) user_data;
  size_t want = size * count, got = 0;
  while (got < want)
  {
    ssize_t n = read(fd, (char*) ptr + got, want - got);
    if (n <= 0) break;
    got += (size_t) n;
  }
  return size ? got / size : 0;
}

// Loads rules saved with save() from an open descriptor (the sandboxed worker cannot open files);
// returns 0 when the data is missing or incompatible.
JNIEXPORT jlong JNICALL
Java_yara_docscan_android_scan_NativeYara_loadFd(JNIEnv* env, jclass cls, jint fd)
{
  YR_STREAM stream = {0};
  stream.user_data = (void*) (intptr_t) fd;
  stream.read = fd_stream_read;
  YR_RULES* rules = NULL;
  lseek(fd, 0, SEEK_SET);
  return yr_rules_load_stream(&stream, &rules) == ERROR_SUCCESS ? (jlong) (intptr_t) rules : 0;
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

static int write_all(int fd, const unsigned char* p, size_t n)
{
  while (n > 0)
  {
    ssize_t w = write(fd, p, n);
    if (w <= 0) return -1;
    p += w;
    n -= (size_t) w;
  }
  return 0;
}

// The PLAN half of docscan_disarm (cli/yara.c do_disarm in the sandbox worker): decide and cure in
// memory, write the cured bytes to out_fd. The broker (app process) does backup / replace / delete.
static void plan_disarm(const uint8_t* data, size_t len, DOCSCAN_STATE* st, int out_fd, strbuf* b)
{
  unsigned char* cured = NULL;
  size_t cured_len = 0;
  char action[256] = "";
  int kind = docscan_disarm_plan(data, len, &st->ds, &cured, &cured_len, action, sizeof(action));
  if (kind == DOCSCAN_DISARM_REPLACE && (out_fd < 0 || write_all(out_fd, cured, cured_len) != 0))
  {
    kind = DOCSCAN_DISARM_FAILED;
    snprintf(action, sizeof(action), "failed:write");
  }
  docscan_disarm_free(cured);
  sb_printf(b, ",\"disarm_result\":{\"kind\":%d,\"action\":\"", kind);
  sb_json(b, action);
  sb_printf(b, "\",\"cured_size\":%zu}", kind == DOCSCAN_DISARM_REPLACE ? cured_len : (size_t) 0);
}

/*
 * Scans an open file descriptor (ownership stays with the caller) -> the docscan JSON object as UTF-8
 * bytes (document strings may hold invalid UTF-8, which NewStringUTF would reject).
 *
 * plan_disarm: when the policy asks for a cure (same condition as cli/yara.c: a HIGH or a meta.disarm
 * action), plan it on the same bytes and add "disarm_result"; the cured file goes to out_fd.
 */
JNIEXPORT jbyteArray JNICALL
Java_yara_docscan_android_scan_NativeYara_scanFd(JNIEnv* env, jclass cls, jlong h, jint fd,
                                                 jstring jname, jstring jdir, jint timeout,
                                                 jboolean jplan, jint out_fd, jint macro_fd)
{
  YR_RULES* rules = (YR_RULES*) (intptr_t) h;
  if (rules == NULL) { throw_ex(env, "rules are not loaded"); return NULL; }

  struct stat sbuf;
  if (fstat(fd, &sbuf) != 0) { throw_ex(env, "fstat failed"); return NULL; }
  size_t len = (size_t) sbuf.st_size;
  const uint8_t* data = (const uint8_t*) "";
  void* map = NULL;
  if (len > 0)
  {
    map = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) { throw_ex(env, "mmap failed"); return NULL; }
    data = (const uint8_t*) map;
  }

  YR_SCANNER* scanner = NULL;
  if (yr_scanner_create(rules, &scanner) != ERROR_SUCCESS)
  {
    if (map) munmap(map, len);
    throw_ex(env, "yr_scanner_create failed");
    return NULL;
  }

  SCAN_ARGS* args = (SCAN_ARGS*) calloc(1, sizeof(SCAN_ARGS));  // ~55 KB: keep it off the stack
  if (args == NULL)
  {
    yr_scanner_destroy(scanner);
    if (map) munmap(map, len);
    throw_ex(env, "out of memory");
    return NULL;
  }

  const char* name = (*env)->GetStringUTFChars(env, jname, NULL);
  const char* dir = (*env)->GetStringUTFChars(env, jdir, NULL);
  file_vars_set(scanner, name, dir, data, len);
  (*env)->ReleaseStringUTFChars(env, jname, name);
  (*env)->ReleaseStringUTFChars(env, jdir, dir);

  yr_scanner_set_callback(scanner, scan_callback, args);
  if (timeout > 0) yr_scanner_set_timeout(scanner, timeout);
  int r = yr_scanner_scan_mem(scanner, data, len);
  yr_scanner_destroy(scanner);

  strbuf out = {0};
  if (r != ERROR_SUCCESS && r != ERROR_SCAN_TIMEOUT)
    sb_printf(&out, "{\"error\":\"scan failed\",\"code\":%d}", r);
  else if (!args->dsc.active)
    sb_puts(&out, "{\"error\":\"docscan module did not run\"}");
  else
  {
    build_docscan_json(rules, &args->dsc, &out);
    out.len--;  // reopen the root object
    out.s[out.len] = '\0';
    if (r == ERROR_SCAN_TIMEOUT) sb_puts(&out, ",\"timeout\":true");
    DOCSCAN_STATE* st = &args->dsc;
    // the decompressed VBA for the macro store (--docscan-extract of the PC watcher)
    if (macro_fd >= 0 && st->vba != NULL && st->vba_len > 0)
      sb_printf(&out, ",\"vba_saved\":%s", write_all(macro_fd, (const unsigned char*) st->vba, st->vba_len) == 0 ? "true" : "false");
    sb_printf(&out, ",\"vba_size\":%zu", st->vba_len);
    if (jplan && st->ds.present && (st->ds.high || st->max_severity == 2))
      plan_disarm(data, len, st, out_fd, &out);
    sb_puts(&out, "}");
  }
  docscan_state_free(&args->dsc);
  free(args);
  if (map) munmap(map, len);
  return to_bytes(env, &out);
}

/*
 * Vendor rules over a piece of data that is not a file of its own (Android: classes*.dex of an APK):
 * returns a JSON array of the matching vendor rules (policy rules and docscan_info indicators excluded),
 * the same selection as the Layer-2 re-scan of the VBA / document parts.
 */
JNIEXPORT jbyteArray JNICALL
Java_yara_docscan_android_scan_NativeYara_scanMem(JNIEnv* env, jclass cls, jlong h, jbyteArray jdata,
                                                  jint len, jstring jname, jint timeout)
{
  YR_RULES* rules = (YR_RULES*) (intptr_t) h;
  if (rules == NULL) { throw_ex(env, "rules are not loaded"); return NULL; }
  jbyte* data = (*env)->GetByteArrayElements(env, jdata, NULL);
  if (data == NULL) return NULL;

  char found[4096] = "";
  char desc[4096] = "";
  YR_SCANNER* sc = NULL;
  if (yr_scanner_create(rules, &sc) == ERROR_SUCCESS)
  {
    const char* name = (*env)->GetStringUTFChars(env, jname, NULL);
    file_vars_set(sc, name, "", (const uint8_t*) data, (size_t) len);
    (*env)->ReleaseStringUTFChars(env, jname, name);
    vmatch_collect vm = {found, sizeof(found), desc, sizeof(desc)};
    yr_scanner_set_callback(sc, vendor_match_cb, &vm);
    if (timeout > 0) yr_scanner_set_timeout(sc, timeout);
    yr_scanner_scan_mem(sc, (const uint8_t*) data, (size_t) len);
    yr_scanner_destroy(sc);
  }
  (*env)->ReleaseByteArrayElements(env, jdata, data, JNI_ABORT);

  strbuf out = {0};
  sb_printf(&out, "{\"rules\":[%s],\"descriptions\":[%s]}", found, desc);
  return to_bytes(env, &out);
}

// ------------------------------------------------ critical information --

typedef struct
{
  const char* names[64];
  int n;
  int size;      // from the first matched rule that has e5_chunk_size
  int overlap;   // ... e5_chunk_overlap
} CRITICAL_MATCHES;

static int critical_callback(YR_SCAN_CONTEXT* context, int message, void* message_data, void* user_data)
{
  if (message == CALLBACK_MSG_RULE_MATCHING)
  {
    YR_RULE* rule = (YR_RULE*) message_data;
    CRITICAL_MATCHES* m = (CRITICAL_MATCHES*) user_data;
    if (m->n < 64) m->names[m->n++] = rule->identifier;
    YR_META* meta;
    yr_rule_metas_foreach(rule, meta)
    {
      if (meta->type != META_TYPE_INTEGER) continue;
      if (m->size == 0 && strcmp(meta->identifier, "e5_chunk_size") == 0) m->size = (int) meta->integer;
      if (m->overlap < 0 && strcmp(meta->identifier, "e5_chunk_overlap") == 0) m->overlap = (int) meta->integer;
    }
  }
  return CALLBACK_CONTINUE;
}

static void iso_utc(time_t t, char* out, size_t osz)
{
  struct tm tmv;
  if (gmtime_r(&t, &tmv) == NULL) { out[0] = '\0'; return; }
  strftime(out, osz, "%Y-%m-%dT%H:%M:%SZ", &tmv);
}

#define CRITICAL_MAX_FILE (100u * 1024 * 1024)

/*
 * Pass 3 (critical_process of cli/yara.c) on a descriptor, in the sandboxed worker: extract the text,
 * scan its normalised copy with the critical rules, on a match build the JSON line (schema 2.0) and
 * write it to out_fd; the broker appends it to the queue. The document text never leaves out_fd.
 * Returns a small status object: {"status":"queued","fragments":N,"rules":[..]} / "nomatch" / "skipped".
 */
JNIEXPORT jbyteArray JNICALL
Java_yara_docscan_android_scan_NativeYara_critical(JNIEnv* env, jclass cls, jlong h, jint fd,
                                                   jstring jname, jstring jpath, jint chunk_size,
                                                   jint chunk_overlap, jint timeout, jint out_fd)
{
  YR_RULES* rules = (YR_RULES*) (intptr_t) h;
  strbuf out = {0};
  if (rules == NULL) { throw_ex(env, "critical rules are not loaded"); return NULL; }

  char received[32];
  iso_utc(time(NULL), received, sizeof(received));

  struct stat sbuf;
  if (fstat(fd, &sbuf) != 0) { throw_ex(env, "fstat failed"); return NULL; }
  size_t size = (size_t) sbuf.st_size;
  if (size == 0 || size > CRITICAL_MAX_FILE)
  {
    sb_puts(&out, size ? "{\"status\":\"skipped\",\"reason\":\"file larger than 100 MB\"}"
                       : "{\"status\":\"skipped\",\"reason\":\"empty file\"}");
    return to_bytes(env, &out);
  }
  void* map = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) { throw_ex(env, "mmap failed"); return NULL; }
  const uint8_t* data = (const uint8_t*) map;

  const char* name = (*env)->GetStringUTFChars(env, jname, NULL);
  const char* path = (*env)->GetStringUTFChars(env, jpath, NULL);
  char ext[16] = "";
  const char* dot = strrchr(name, '.');
  if (dot != NULL && strlen(dot + 1) < sizeof(ext))
  {
    size_t k = 0;
    for (const char* c = dot + 1; *c; c++) ext[k++] = (char) ((*c >= 'A' && *c <= 'Z') ? *c + 32 : *c);
    ext[k] = '\0';
  }

  docscan_text_t t;
  int rc = docscan_text_extract(data, size, ext, &t);
  if (rc != DOCSCAN_TEXT_OK)
  {
    sb_puts(&out, "{\"status\":\"skipped\",\"reason\":\"");
    sb_json(&out, docscan_text_strerror(rc));
    sb_puts(&out, "\"}");
    goto done;
  }

  size_t nlen = 0;
  char* norm = docscan_text_normalize(t.text, t.len, &nlen);
  CRITICAL_MATCHES m;
  memset(&m, 0, sizeof(m));
  m.overlap = -1;
  int sr = norm ? yr_rules_scan_mem(rules, (const uint8_t*) norm, nlen, SCAN_FLAGS_FAST_MODE,
                                    critical_callback, &m, timeout)
                : ERROR_INSUFFICIENT_MEMORY;
  free(norm);
  if (sr != ERROR_SUCCESS)
  {
    sb_printf(&out, "{\"status\":\"error\",\"reason\":\"scan error %d\"}", sr);
    docscan_text_free(&t);
    goto done;
  }
  if (m.n == 0)
  {
    sb_puts(&out, "{\"status\":\"nomatch\"}");
    docscan_text_free(&t);
    goto done;
  }

  // chunking: rule meta, then the setting, then 700/120
  int csize = m.size > 0 ? m.size : (chunk_size > 0 ? chunk_size : 700);
  int cover = m.overlap >= 0 ? m.overlap : (chunk_overlap >= 0 ? chunk_overlap : 120);
  if (csize < 200 || csize > 1500 || cover < 0 || cover > csize / 2)
  {
    sb_printf(&out, "{\"status\":\"error\",\"reason\":\"invalid chunk size/overlap %d,%d\"}", csize, cover);
    docscan_text_free(&t);
    goto done;
  }

  char sha[65];
  docscan_sha256_hex(data, size, sha);
  char fs_modified[32] = "";
  if (!t.modified_at[0]) iso_utc(sbuf.st_mtime, fs_modified, sizeof(fs_modified));

  docscan_critical_doc d;
  memset(&d, 0, sizeof(d));
  d.name = name;
  d.path = path;
  d.format = ext[0] ? ext : t.kind;
  d.size_bytes = size;
  d.sha256 = sha;
  d.author = t.author;
  d.last_modified_by = t.last_modified_by;
  d.title = t.title;
  d.created_at = t.created_at;
  d.modified_at = t.modified_at[0] ? t.modified_at : fs_modified;
  d.received_at = received;
  d.matches = m.names;
  d.n_matches = m.n;
  d.chunk_size = csize;
  d.chunk_overlap = cover;

  size_t jl = 0;
  int nfrag = 0;
  char* json = docscan_critical_json(t.text, t.len, &d, &jl, &nfrag);
  docscan_text_free(&t);
  if (json == NULL)
  {
    sb_puts(&out, "{\"status\":\"error\",\"reason\":\"could not build the JSON\"}");
    goto done;
  }
  int written = out_fd >= 0 && write_all(out_fd, (const unsigned char*) json, jl) == 0;
  free(json);
  if (!written)
  {
    sb_puts(&out, "{\"status\":\"error\",\"reason\":\"could not write the queue line\"}");
    goto done;
  }
  sb_printf(&out, "{\"status\":\"queued\",\"fragments\":%d,\"rules\":[", nfrag);
  for (int i = 0; i < m.n; i++)
  {
    sb_puts(&out, i ? ",\"" : "\"");
    sb_json(&out, m.names[i]);
    sb_puts(&out, "\"");
  }
  sb_puts(&out, "]}");

done:
  (*env)->ReleaseStringUTFChars(env, jname, name);
  (*env)->ReleaseStringUTFChars(env, jpath, path);
  munmap(map, size);
  return to_bytes(env, &out);
}
