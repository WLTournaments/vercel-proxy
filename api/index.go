package api

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
)

func internalServerError(w http.ResponseWriter, err error) {
	if err != nil {
		log.Printf("Internal server error: %v", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func Handler(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			log.Printf("WithHandler panic: %v", err)
			http.Error(w, fmt.Sprintf("internal server error: %v", err), http.StatusInternalServerError)
		}
	}()

	htmlProxy := os.Getenv("HTTP_PROXY_ENABLE") == "true"

	// Set the CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, X-PROXY-HOST, X-PROXY-SCHEME")

	// Handle the OPTIONS preflight request
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get the URL to proxy
	targetURL := getTargetURL(r)
	if targetURL == "" {
		http.Error(w, "invalid url", http.StatusBadRequest)
		return
	}

	// Create a new request
	req, err := http.NewRequest(r.Method, targetURL, r.Body)
	if err != nil {
		internalServerError(w, err)
		return
	}

	// Copy headers from the original request
	copyHeaders(req.Header, r.Header)

	if htmlProxy && r.Header.Get("Accept-Encoding") != "" {
		if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			req.Header.Set("Accept-Encoding", "gzip")
		}
	}

	// Send the request to the target server
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Disable following redirects
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		internalServerError(w, err)
		return
	}
	defer resp.Body.Close()

	// Handle redirects
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if location != "" {
			w.Header().Set("Location", rewriteURL(location, r))
		}
	}

	if err := proxyResponse(w, resp, r); err != nil {
		internalServerError(w, err)
		return
	}
}

func getTargetURL(r *http.Request) string {
	re := regexp.MustCompile(`^/*(https?:)/*`)
	u := re.ReplaceAllString(r.URL.Path, "$1//")
	if r.URL.RawQuery != "" {
		u += "?" + r.URL.RawQuery
	}
	if !strings.HasPrefix(u, "http") {
		return ""
	}
	return u
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func proxyResponse(w http.ResponseWriter, resp *http.Response, req *http.Request) error {
	// Copy headers from the proxied response
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}

	// Rewrite certain headers
	if referer := w.Header().Get("Referer"); referer != "" {
		w.Header().Set("Referer", req.Host)
	}

	// Rewrite URLs in Location header
	if location := w.Header().Get("Location"); location != "" {
		w.Header().Set("Location", rewriteURL(location, req))
	}

	// Set the status code
	w.WriteHeader(resp.StatusCode)

	// Copy the response body
	_, err := io.Copy(w, resp.Body)
	return err
}

func rewriteURL(originalURL string, r *http.Request) string {
	u, err := url.Parse(originalURL)
	if err != nil {
		return originalURL
	}

	// Construct the new URL
	newURL := fmt.Sprintf("%s://%s/%s://%s%s", r.URL.Scheme, r.Host, u.Scheme, u.Host, u.Path)
	if u.RawQuery != "" {
		newURL += "?" + u.RawQuery
	}
	return newURL
}
