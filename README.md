Install ESPnet including the compiled Kaldi: [Install ESPnet](https://espnet.github.io/espnet/installation.html).

Edit the ESPnet path in `decode.sh`.

Create the configuration file `.env`:

```
DB_HOST=localhost
DB_PORT=5432
DB_USER=test
DB_NAME=test
SESSION_KEY=test
URL_BASE=http://localhost:8080
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=test
SMTP_PASSWORD=test
DATA_DIR=data
DECODE_CMD=./decode.sh
```

Build and run the web server:

```
go build cmd/web/main.go
nohup ./main > main.log &
```

Build and run the transcriber daemon:

```
go build -o transcriber cmd/transcriber/main.go
nohup ./transcriber > transcriber.log &
```
