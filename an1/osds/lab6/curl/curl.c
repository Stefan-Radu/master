#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
	return fwrite(ptr, size, nmemb, (FILE *) userdata);
}
 
int main() {
    CURL *curl;
    CURLcode res;
    FILE * f = NULL; 

    const char* api_key = getenv("VT_API_KEY");
    char header[200] = "x-apikey:";
    strcat(header, api_key);

    char *sha = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
    char url[200] = "https://www.virustotal.com/api/v3/files/";
    strcat(url, sha);
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
 
        f = fopen("tmp.txt", "w+");
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, f);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, header);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        /* Perform the request, res will get the return code */ 
        res = curl_easy_perform(curl);
        /* Check for errors */ 
        if(res != CURLE_OK) {
          fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
        } else {
            // Get the response code
            long response_code;
            res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);

            if((res == CURLE_OK) && (response_code == 200)) {
                printf("Found: %ld\n", response_code);
            } else {
                printf("Not found: %ld\n", response_code);
            }
        }
 
        /* always cleanup */ 
        curl_easy_cleanup(curl);
    }
    return 0;
}
