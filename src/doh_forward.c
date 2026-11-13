#include "./include/doh_forward.h"

#include <ctype.h>
#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct pending {
    CURL *easy;            
    void *ctx;
    uint8_t client_id[2];
    uint8_t question[260];  
    size_t question_len;
    uint8_t *resp;
    size_t resp_len;
} pending_type;

static CURLM *multi;
static struct curl_slist *headers;
static const char *doh_url;
static const char *cafile;
static long timeout_ms;
static bool insecure_tls;
static doh_done_fn done_cb;
static pending_type slots[DOH_MAX_PENDING];

static size_t write_cb(char *data, size_t size, size_t nmemb, void *userdata) {
    pending_type *req = userdata;
    size_t n = size * nmemb;

    // vacsie ako najvacsia DNS sprava -> 0 zrusi prenos -> SERVFAIL
    if(req->resp_len + n > 65535) {
        return 0;
    }
    uint8_t *tmp = realloc(req->resp, req->resp_len + n);
    if(tmp == NULL) {
        return 0;
    }
    req->resp = tmp;
    memcpy(req->resp + req->resp_len, data, n);
    req->resp_len += n;
    return n;
}

static void finish(pending_type *req, bool ok) {
    curl_multi_remove_handle(multi, req->easy);
    curl_easy_cleanup(req->easy);

    void *ctx = req->ctx;
    uint8_t *resp = req->resp;
    size_t resp_len = req->resp_len;
    memset(req, 0, sizeof(pending_type));

    if(ok) {
        done_cb(ctx, resp, resp_len);
    } else {
        done_cb(ctx, NULL, 0);
    }
    free(resp);
}

int doh_init(const char *url, unsigned timeout, bool insecure, doh_done_fn done) {
    if(curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
        return -1;
    }
    doh_url = url;
    timeout_ms = (long)timeout * 1000;
    insecure_tls = insecure;
    done_cb = done;

    cafile = getenv("SSL_CERT_FILE");

    headers = curl_slist_append(headers, "Content-Type: application/dns-message");
    headers = curl_slist_append(headers, "Accept: application/dns-message");
    headers = curl_slist_append(headers, "Expect:");
    multi = curl_multi_init();
    if(headers == NULL || multi == NULL) {
        return -1;
    }

    fprintf(stderr, "outstanding upstream request cap: %d\n", DOH_MAX_PENDING);
    return 0;
}

pending_type* doh_submit(const uint8_t *query, size_t query_len, void *ctx) {

    pending_type *req = NULL;
    for(int i = 0; i < DOH_MAX_PENDING; i++) {
        if(slots[i].easy == NULL) {
            req = &slots[i];
            break;
        }
    }
    if(req == NULL) {
        return NULL;
    }

    size_t i = 12;
    while(i < query_len && query[i] != 0) {
        i += query[i] + 1;
    }
    if(i + 5 > query_len || i + 5 - 12 > sizeof(req->question)) {
        return NULL;
    }

    req->easy = curl_easy_init();
    if(req->easy == NULL) {
        return NULL;
    }
    req->ctx = ctx;
    req->question_len = i + 5 - 12;
    memcpy(req->question, query + 12, req->question_len);
    memcpy(req->client_id, query, 2);


    static uint8_t body[65535];
    memcpy(body, query, query_len);
    body[0] = 0;
    body[1] = 0;

    CURL *e = req->easy;
    curl_easy_setopt(e, CURLOPT_URL, doh_url);
    curl_easy_setopt(e, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(e, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(e, CURLOPT_POSTFIELDSIZE, (long)query_len);
    curl_easy_setopt(e, CURLOPT_COPYPOSTFIELDS, (const char *)body);
    curl_easy_setopt(e, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(e, CURLOPT_WRITEDATA, req);
    curl_easy_setopt(e, CURLOPT_PRIVATE, req);
    curl_easy_setopt(e, CURLOPT_TIMEOUT_MS, timeout_ms);
    curl_easy_setopt(e, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(e, CURLOPT_FOLLOWLOCATION, 0L);
    curl_easy_setopt(e, CURLOPT_SSL_VERIFYPEER, insecure_tls ? 0L : 1L);
    curl_easy_setopt(e, CURLOPT_SSL_VERIFYHOST, insecure_tls ? 0L : 2L);
    if(cafile != NULL && cafile[0] != '\0') {
        curl_easy_setopt(e, CURLOPT_CAINFO, cafile);
    }

    if(curl_multi_add_handle(multi, e) != CURLM_OK) {
        curl_easy_cleanup(e);
        memset(req, 0, sizeof(pending_type));
        return NULL;
    }
    return req;
}

void doh_cancel(pending_type *req) {
    if(req == NULL || req->easy == NULL) {
        return;
    }
    curl_multi_remove_handle(multi, req->easy);
    curl_easy_cleanup(req->easy);
    free(req->resp);
    memset(req, 0, sizeof(pending_type));
}

int doh_poll(struct pollfd *fds, int n, int timeout_ms) {
    struct curl_waitfd wfds[DOH_MAX_FDS];
    if(n > DOH_MAX_FDS) {
        n = DOH_MAX_FDS;
    }
    for(int i = 0; i < n; i++) {
        wfds[i].fd = fds[i].fd;
        wfds[i].events = 0;
        if(fds[i].events & POLLIN) {
            wfds[i].events |= CURL_WAIT_POLLIN;
        }
        if(fds[i].events & POLLOUT) {
            wfds[i].events |= CURL_WAIT_POLLOUT;
        }
        wfds[i].revents = 0;
    }

    int ready = 0;
    curl_multi_poll(multi, wfds, (unsigned)n, timeout_ms, &ready);

    int count = 0;
    for(int i = 0; i < n; i++) {
        fds[i].revents = 0;
        if(wfds[i].revents & CURL_WAIT_POLLIN) {
            fds[i].revents |= POLLIN;
        }
        if(wfds[i].revents & CURL_WAIT_POLLOUT) {
            fds[i].revents |= POLLOUT;
        }
        if(fds[i].revents != 0) {
            count++;
        }
    }

    int running;
    curl_multi_perform(multi, &running);

    CURLMsg *msg;
    int left;
    while((msg = curl_multi_info_read(multi, &left)) != NULL) {
        if(msg->msg != CURLMSG_DONE) {
            continue;
        }
        CURLcode result = msg->data.result;
        pending_type *req;
        curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, (char **)&req);

        long http_code = 0;
        curl_easy_getinfo(req->easy, CURLINFO_RESPONSE_CODE, &http_code);
        uint8_t *r = req->resp;
        size_t len = req->resp_len;
        bool ok = false;

        if(result != CURLE_OK) {
            fprintf(stderr, "doh: %s\n", curl_easy_strerror(result));
        } else if(http_code < 200 || http_code > 299) {
            fprintf(stderr, "doh: upstream returned HTTP %ld\n", http_code);
        } else if(len >= 12 + req->question_len && (r[2] & 0x80) != 0 && ((r[2] >> 3) & 0x0F) == 0
                  && r[4] == 0 && r[5] == 1) {

            size_t name_len = req->question_len - 4;
            ok = true;
            for(size_t j = 0; j < name_len; j++) {
                if(tolower(r[12 + j]) != tolower(req->question[j])) {
                    ok = false;
                }
            }
            if(memcmp(r + 12 + name_len, req->question + name_len, 4) != 0) {
                ok = false;
            }
        }
        if(ok) {
            memcpy(r, req->client_id, 2);
        } else if(result == CURLE_OK && http_code >= 200 && http_code <= 299) {
            fprintf(stderr, "doh: invalid DNS message from upstream\n");
        }
        finish(req, ok);
    }
    return count;
}

void doh_shutdown() {
    for(int i = 0; i < DOH_MAX_PENDING; i++) {
        if(slots[i].easy != NULL) {
            finish(&slots[i], false);
        }
    }
}

void doh_cleanup() {
    for(int i = 0; i < DOH_MAX_PENDING; i++) {
        doh_cancel(&slots[i]);
    }
    curl_multi_cleanup(multi);
    curl_slist_free_all(headers);
    curl_global_cleanup();
}