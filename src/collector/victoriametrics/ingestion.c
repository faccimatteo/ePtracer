#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>

#include "log.h"

int ingest(const char *syscall_event)
{
    CURL *curl_handle;
    CURLcode res;

    curl_handle = curl_easy_init();
    if(curl_handle) {
        curl_easy_setopt(curl_handle, CURLOPT_URL, "http://localhost:8428/api/v1/import/prometheus");
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, syscall_event);
        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");

        res = curl_easy_perform(curl_handle);

        if(res != CURLE_OK) {
            log_error("error: %s\n", curl_easy_strerror(res));
            curl_easy_cleanup(curl_handle);
            return 1;
        }

        curl_easy_cleanup(curl_handle);
    } else {
        log_error("Failed to initialize curl\n");
        return 1;
    }
    return 0;
}
