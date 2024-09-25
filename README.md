# Light Forward Proxy
Light Forward Proxy is a super simple lightweight HTTP/HTTPS forward proxy. It supports the CONNECT method for HTTPS and removes proxy-specific headers to ensure smooth operation.

## Installation
1. Clone the repository:
```bash
git clone https://github.com/yourusername/light-forward-proxy.git
```

2. Build the project:
```bash
go build -o main
```

3. Run the proxy server:
```bash
./main -listen 0.0.0.0 -port 8080
```

## Usage
After starting the server, configure your system or application to use the proxy by setting your server’s IP address and port 8080.

## Options
- -listen — IP address to listen on (default: 0.0.0.0).
- -port — Port to listen on (default: 8080).

## License
MIT
