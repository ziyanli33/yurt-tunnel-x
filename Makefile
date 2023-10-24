build:
	go build -o bin/yurt-tunnel-server ./cmd/yurt-tunnel-server
	go build -o bin/yurt-tunnel-agent ./cmd/yurt-tunnel-agent
	go build -o bin/simple-https-server ./cmd/simple-https-server
certs:
	openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=State/L=Local/O=Org/CN=www.example.com" \
        -keyout certs/ca.key  -out certs/ca.crt
