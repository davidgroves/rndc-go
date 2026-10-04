package rndc_test

import (
	"fmt"
	"log"

	"github.com/davidgroves/rndc-go"
	"github.com/miekg/dns"
)

func ExampleParseAlgorithm() {
	a, err := rndc.ParseAlgorithm("hmac-sha256")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(a)
	fmt.Println(a.TSIGName() == dns.HmacSHA256)
	// Output:
	// sha256
	// true
}

func ExampleConfig() {
	cfg := rndc.Config{
		Host:      "127.0.0.1",
		Port:      953,
		Algorithm: rndc.SHA256,
		Secret:    "c2VjcmV0LWtleS1mb3ItdGVzdGluZy1vbmx5",
	}
	fmt.Println(cfg.Host, cfg.Port, cfg.Algorithm)
	// Output:
	// 127.0.0.1 953 sha256
}
