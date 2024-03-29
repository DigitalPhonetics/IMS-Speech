Install ESPnet including the compiled Kaldi: [Install ESPnet](https://espnet.github.io/espnet/installation.html).

Edit the ESPnet path in `decode.sh`.

Download external models:

```
cd models
./download.sh
```

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

Alternatively, run the decoding from the command line:

```
./decode.sh $FILE $LANGUAGE
```

`$LANGUAGE` can be `en`, `de` or `ru`.
The result will be written to `$FILENAME.txt`.

Citation:

```
@article{denisov2019ims,
  title={IMS-speech: A speech to text tool},
  author={Denisov, Pavel and Vu, Ngoc Thang},
  journal={Studientexte zur Sprachkommunikation: Elektronische Sprachsignalverarbeitung 2019},
  pages={170--177},
  year={2019},
  publisher={TUDpress, Dresden}
}
```
