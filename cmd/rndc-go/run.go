package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/davidgroves/rndc-go"
	"github.com/spf13/pflag"
)

type rndcCaller interface {
	Call(ctx context.Context, command string) (rndc.Response, error)
	Close() error
}

var dialFunc = func(ctx context.Context, cfg rndc.Config) (rndcCaller, error) {
	return rndc.Dial(ctx, cfg)
}

func run(args []string, stdout, stderr io.Writer, lookupEnv func(string) (string, bool)) int {
	fs := pflag.NewFlagSet("rndc-go", pflag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.SortFlags = false
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: rndc-go [options] COMMAND [args...]\n\n")
		fmt.Fprintf(stderr, "Go client for ISC BIND's RNDC.\n")
		fmt.Fprintf(stderr, "COMMAND is the RNDC command to execute (e.g. status, zonestatus example.com).\n\n")
		fs.PrintDefaults()
	}

	var (
		host, algorithm, secret string
		port, timeout           int
		showVersion, help       bool
	)

	fs.StringVarP(&host, "host", "s", envOr(lookupEnv, rndc.EnvHost, ""), "RNDC server hostname or IP")
	fs.IntVarP(&port, "port", "p", envInt(lookupEnv, rndc.EnvPort, 0), "RNDC server port")
	fs.StringVarP(&algorithm, "algorithm", "a", envOr(lookupEnv, rndc.EnvAlgorithm, ""), "TSIG algorithm")
	fs.StringVarP(&secret, "secret", "k", envOr(lookupEnv, rndc.EnvSecret, ""), "Base64-encoded RNDC secret key")
	fs.IntVarP(&timeout, "timeout", "t", envInt(lookupEnv, rndc.EnvTimeout, 10), "Connection timeout in seconds")
	fs.BoolVarP(&showVersion, "version", "V", false, "print version and exit")
	fs.BoolVarP(&help, "help", "h", false, "show help")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			return 0
		}
		fmt.Fprintln(stderr, err)
		return 2
	}

	if help {
		fs.Usage()
		return 0
	}

	if showVersion {
		fmt.Fprintf(stdout, "rndc-go %s\n", programVersion())
		return 0
	}

	commandParts := fs.Args()
	if len(commandParts) == 0 {
		fmt.Fprintln(stderr, "Missing argument COMMAND")
		return 2
	}

	if host == "" {
		fmt.Fprintf(stderr, "Missing --host or %s environment variable\n", rndc.EnvHost)
		return 1
	}
	if port == 0 {
		fmt.Fprintf(stderr, "Missing --port or %s environment variable\n", rndc.EnvPort)
		return 1
	}
	if algorithm == "" {
		fmt.Fprintf(stderr, "Missing --algorithm or %s environment variable\n", rndc.EnvAlgorithm)
		return 1
	}
	if secret == "" {
		fmt.Fprintf(stderr, "Missing --secret or %s environment variable\n", rndc.EnvSecret)
		return 1
	}

	algo, err := rndc.ParseAlgorithm(algorithm)
	if err != nil {
		fmt.Fprintf(stderr, "Invalid value for --algorithm: %s\n", algorithm)
		return 2
	}

	cfg := rndc.Config{
		Host:      host,
		Port:      port,
		Algorithm: algo,
		Secret:    secret,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	ctx := context.Background()
	client, err := dialFunc(ctx, cfg)
	if err != nil {
		return printDialError(stderr, err)
	}
	defer func() { _ = client.Close() }()

	result, err := client.Call(ctx, strings.Join(commandParts, " "))
	if err != nil {
		return printDialError(stderr, err)
	}

	if text := result.Text(); text != "" {
		fmt.Fprintln(stdout, text)
	} else if errText := result.Err(); errText != "" {
		fmt.Fprintln(stderr, errText)
		return 1
	} else if len(result) > 0 {
		for key, value := range result {
			if key == "type" || key == "result" {
				continue
			}
			fmt.Fprintf(stdout, "%s: %s\n", key, value)
		}
	}

	if result["result"] != "" && result["result"] != "0" {
		code, convErr := strconv.Atoi(result["result"])
		if convErr != nil {
			return 1
		}
		return code
	}
	return 0
}

func printDialError(stderr io.Writer, err error) int {
	switch {
	case errors.Is(err, rndc.ErrConnection):
		fmt.Fprintf(stderr, "Connection error: %v\n", err)
	case isConfigError(err):
		fmt.Fprintf(stderr, "Configuration error: %v\n", err)
	default:
		fmt.Fprintln(stderr, err)
	}
	return 1
}

func isConfigError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "required") ||
		strings.Contains(s, "invalid") ||
		strings.Contains(s, "secret") ||
		strings.Contains(s, "algorithm") ||
		strings.Contains(s, "port")
}

func envOr(lookup func(string) (string, bool), key, def string) string {
	if lookup == nil {
		return def
	}
	if v, ok := lookup(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(lookup func(string) (string, bool), key string, def int) int {
	s := envOr(lookup, key, "")
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
