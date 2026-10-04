# rndc-go

Go client library and CLI for ISC BIND's RNDC (Remote Name Daemon Control) protocol.

## Requirements

- Go 1.26 or later

## Installation

Library:

```bash
go get github.com/davidgroves/rndc-go
```

CLI:

```bash
go install github.com/davidgroves/rndc-go/cmd/rndc-go@latest
```

### Command-line interface

```bash
# Using CLI options
rndc-go -s 127.0.0.1 -p 953 -a sha256 -k <base64-secret> status

# Using environment variables
export RNDC_HOST=127.0.0.1
export RNDC_PORT=953
export RNDC_ALGORITHM=sha256
export RNDC_SECRET=<base64-secret>
rndc-go status

# Mix of both (CLI options override env vars)
rndc-go --port 954 reload
```

## Configuration

The client can read its settings from environment variables (or a `.env` file):

- `RNDC_HOST`
- `RNDC_PORT`
- `RNDC_ALGORITHM` (e.g. `hmac-sha256`)
- `RNDC_SECRET`
- `RNDC_TIMEOUT`
- `RNDC_MAX_RETRIES`
- `RNDC_RETRY_DELAY`

You can also configure the client in Go:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/davidgroves/rndc-go"
)

func main() {
	client, err := rndc.Dial(context.Background(), rndc.Config{
		Host:      "127.0.0.1",
		Port:      953,
		Algorithm: rndc.SHA256,
		Secret:    "your-base64-secret-here",
		Timeout:   10 * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	resp, err := client.Call(context.Background(), "status")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(resp.Text())
}
```

All of host, port, algorithm, and secret can also be supplied via `rndc.ConfigFromEnv()`.

`ParseAlgorithm` accepts BIND names (`sha256`, `hmac-sha256`) and miekg/dns TSIG names (`dns.HmacSHA256`). Zone helpers take `dns.Class` via `rndc.WithClass`.

HMAC-MD5 is supported because BIND still speaks it; prefer SHA-256 or stronger.

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for build, test, and release instructions.
