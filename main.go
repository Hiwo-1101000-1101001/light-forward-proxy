package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

type ProxyHandler struct {
	secret []byte
}

func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// logging of input requests
	p.logRequest(req)

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
	io.Copy(NewCryptWriter(w, p.secret), NewCryptReader(resp.Body, p.secret))
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

	go transfer(NewCryptWriteCloser(destConn, p.secret), NewCryptReadCloser(clientConn, p.secret))
	transfer(NewCryptWriteCloser(clientConn, p.secret), NewCryptReadCloser(destConn, p.secret))
}

func (p *ProxyHandler) logRequest(req *http.Request) {
	fmt.Printf("Received request:\n")
	fmt.Printf("Method: %s\n", req.Method)
	fmt.Printf("URL: %s\n", req.URL.String())
	fmt.Printf("Protocol: %s\n", req.Proto)
	fmt.Printf("Headers: %v\n", req.Header)
	fmt.Printf("Host: %s\n", req.Host)
	fmt.Printf("RemoteAddr: %s\n", req.RemoteAddr)
	fmt.Println("-----")
}

func transfer(dest io.WriteCloser, src io.ReadCloser) {
	defer dest.Close()
	defer src.Close()
	io.Copy(dest, src)
}

func removeProxyHeaders(req *http.Request) {
	headers := []string{
		"Proxy-Connection", "Proxy-Authenticate", "Proxy-Authorization", "Connection", "TE",
		"Trailers", "Transfer-Encoding", "Upgrade",
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

func NewCryptReader(r io.Reader, key []byte) io.Reader {
	return &cryptReader{r, key}
}

func NewCryptWriter(w io.Writer, key []byte) io.Writer {
	return &cryptWriter{w, key}
}

func NewCryptReadCloser(rc io.ReadCloser, key []byte) io.ReadCloser {
	return &cryptReadCloser{cryptReader{rc, key}, rc}
}

func NewCryptWriteCloser(wc io.WriteCloser, key []byte) io.WriteCloser {
	return &cryptWriteCloser{cryptWriter{wc, key}, wc}
}

type cryptReader struct {
	r   io.Reader
	key []byte
}

func (c *cryptReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if err != nil {
		return n, err
	}
	crypt(p[:n], c.key)
	return n, nil
}

type cryptWriter struct {
	w   io.Writer
	key []byte
}

func (c *cryptWriter) Write(p []byte) (int, error) {
	crypt(p, c.key)
	return c.w.Write(p)
}

type cryptReadCloser struct {
	cryptReader
	rc io.ReadCloser
}

func (c *cryptReadCloser) Close() error {
	return c.rc.Close()
}

type cryptWriteCloser struct {
	cryptWriter
	wc io.WriteCloser
}

func (c *cryptWriteCloser) Close() error {
	return c.wc.Close()
}

func crypt(data, key []byte) {
	keyLen := len(key)
	for i := range data {
		data[i] ^= key[i%keyLen]
	}
}

func generateRandomKey(size int) ([]byte, error) {
	key := make([]byte, size)
	_, err := rand.Read(key)
	return key, err
}

func main() {
	var listenAddr, port string
	flag.StringVar(&listenAddr, "listen", "0.0.0.0", "Address to listen on")
	flag.StringVar(&port, "port", "8081", "Port to listen on")
	flag.Parse()

	key, err := generateRandomKey(32)
	if err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}
	log.Printf("Encryption key: %x", key)

	server := &http.Server{
		Addr:         net.JoinHostPort(listenAddr, port),
		Handler:      &ProxyHandler{secret: key},
		ReadTimeout:  1 * time.Second,
		WriteTimeout: 1 * time.Second,
		IdleTimeout:  1 * time.Second,
	}

	log.Printf("Starting proxy server on %s:%s", listenAddr, port)
	log.Fatal(server.ListenAndServe())
}
