package main

import (
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

// ProxyHandler обрабатывает входящие HTTP и HTTPS запросы
type ProxyHandler struct{}

// ServeHTTP реализует интерфейс http.Handler
func (p *ProxyHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		p.handleHTTPS(w, req)
	} else {
		p.handleHTTP(w, req)
	}
}

// handleHTTP обрабатывает обычные HTTP-запросы
func (p *ProxyHandler) handleHTTP(w http.ResponseWriter, req *http.Request) {
	// Создаем новый запрос на основе исходного
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	
	// Удаляем прокси-заголовки, чтобы избежать конфликтов
	removeProxyHeaders(req)

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, "Ошибка при обращении к целевому серверу: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Копируем заголовки ответа
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)

	// Копируем тело ответа
	io.Copy(w, resp.Body)
}

// handleHTTPS обрабатывает HTTPS-запросы методом CONNECT
func (p *ProxyHandler) handleHTTPS(w http.ResponseWriter, req *http.Request) {
	// Устанавливаем соединение с целевым сервером
	destConn, err := net.DialTimeout("tcp", req.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "Не удалось установить соединение: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer destConn.Close()

	// Отсылаем клиенту ответ 200 Connection Established
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking не поддерживается", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, "Hijacking не удалось: "+err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer clientConn.Close()

	// Отправляем подтверждение клиенту
	_, err = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	if err != nil {
		log.Printf("Ошибка при отправке подтверждения: %v", err)
		return
	}

	// Проксируем данные между клиентом и целевым сервером
	go transfer(destConn, clientConn)
	transfer(clientConn, destConn)
}

// transfer копирует данные из одного соединения в другое
func transfer(dest io.WriteCloser, src io.ReadCloser) {
	defer dest.Close()
	defer src.Close()
	io.Copy(dest, src)
}

// removeProxyHeaders удаляет специфичные для прокси заголовки
func removeProxyHeaders(req *http.Request) {
	// Удаляем заголовки, которые могут вызвать проблемы при пересылке
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("TE")
	req.Header.Del("Trailers")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Upgrade")
}

// copyHeader копирует заголовки из src в dst
func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		// Пропускаем определенные заголовки, если необходимо
		// Например, можно удалить заголовок "Content-Length", если нужно
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {
	// Задаем флаги для порта и адреса прослушивания
	var (
		listenAddr string
		port       string
	)
	flag.StringVar(&listenAddr, "listen", "0.0.0.0", "Адрес для прослушивания")
	flag.StringVar(&port, "port", "8080", "Порт для прослушивания")
	flag.Parse()

	address := net.JoinHostPort(listenAddr, port)

	// Создаем экземпляр прокси-хендлера
	proxy := &ProxyHandler{}

	// Настраиваем HTTP-сервер
	server := &http.Server{
		Addr:         address,
		Handler:      proxy,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("Запуск HTTP/HTTPS прокси-сервера на %s", address)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Ошибка запуска сервера: %v", err)
	}
}
