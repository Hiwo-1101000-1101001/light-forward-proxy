package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type ProxyHandler struct{}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleHTTPS(w, req)
	} else {
		p.handleHTTP(w, req)
	}
}

func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	client := &http.Client{Timeout: 30 * time.Second}
	removeProxyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Target server error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func (p *ProxyHandler) handleHTTPS(w http.ResponseWriter, req *http.Request) {
	destConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Connection failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking failed: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Confirmation error: %v", err)
		return
	}

	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
}

func transfer(dest io.WriteCloser, src io.ReadCloser) {
	defer dest.Close()
	defer src.Close()
	io.Copy(dest, src)
}

func removeProxyHeaders(req *http.Request) {
	headers := []string{
		"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", 
		"Keep-Alive", "TE", "Trailers", "Transfer-Encoding", "Upgrade",
	}
	for _, h := range headers {
		req.Header.Del(h)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	var listenAddr, port string
	flag.StringVar(&listenAddr, "listen", "0.0.0.0", "Address to listen on")
	flag.StringVar(&port, "port", "8080", "Port to listen on")
	flag.Parse()

	server := &http.Server{
		Addr:         net.JoinHostPort(listenAddr, port),
		Handler:      &ProxyHandler{},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Starting proxy server on %s:%s", listenAddr, port)
	log.Fatal(server.ListenAndServe())
}