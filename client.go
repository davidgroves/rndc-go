package rndc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Client is an RNDC session talking to a BIND named process.
type Client struct {
	cfg    Config
	secret []byte

	mu     sync.Mutex
	conn   net.Conn
	serial uint32
	nonce  []byte
}

// Dial connects to the RNDC server and performs the null-command handshake.
func Dial(ctx context.Context, cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	secret, err := cfg.decodedSecret()
	if err != nil {
		return nil, fmt.Errorf("invalid secret key format: %w", err)
	}
	c := &Client{cfg: cfg, secret: secret, serial: randomSerial()}
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	return c, nil
}

func randomSerial() uint32 {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return uint32(time.Now().UnixNano() & 0xffffff)
	}
	return binary.BigEndian.Uint32(b[:]) & 0xffffff
}

func (c *Client) connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.cfg.Host, strconv.Itoa(c.cfg.Port))
	var last error
	attempts := c.cfg.MaxRetries
	if attempts < 1 {
		attempts = 1
	}
	for i := 0; i < attempts; i++ {
		if i > 0 && c.cfg.RetryDelay > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("%w: %v", ErrConnection, ctx.Err())
			case <-time.After(c.cfg.RetryDelay):
			}
		}
		dctx, cancel := withTimeout(ctx, c.cfg.Timeout)
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(dctx, "tcp", addr)
		cancel()
		if err != nil {
			last = fmt.Errorf("%w: failed to connect to %s: %v", ErrConnection, addr, err)
			continue
		}
		c.conn = conn
		c.nonce = nil
		resp, err := c.command(ctx, map[string]string{"type": "null"})
		if err != nil {
			_ = conn.Close()
			c.conn = nil
			last = err
			continue
		}
		ctrl := resp.getDict("_ctrl")
		if ctrl == nil {
			_ = conn.Close()
			c.conn = nil
			last = fmt.Errorf("%w: missing _ctrl in handshake", ErrConnection)
			continue
		}
		c.nonce = append([]byte(nil), ctrl.getRaw("_nonce")...)
		if len(c.nonce) == 0 {
			c.nonce = nil
		}
		return nil
	}
	if last == nil {
		last = ErrConnection
	}
	return last
}

func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return context.WithCancel(ctx)
	}
	if deadline, ok := ctx.Deadline(); ok {
		if time.Until(deadline) <= d {
			return context.WithCancel(ctx)
		}
	}
	return context.WithTimeout(ctx, d)
}

func (c *Client) ensureConn(ctx context.Context) error {
	if c.conn != nil {
		return nil
	}
	return c.connect(ctx)
}

func (c *Client) closeLocked() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
	c.nonce = nil
}

// Close closes the RNDC TCP connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	err := c.conn.Close()
	c.conn = nil
	c.nonce = nil
	return err
}

func (c *Client) prepare(data map[string]string) ([]byte, error) {
	c.serial++
	now := time.Now().Unix()
	msg := newDict()
	auth := newDict()
	msg.setDict("_auth", auth)
	ctrl := newDict()
	ctrl.setString("_ser", strconv.FormatUint(uint64(c.serial), 10))
	ctrl.setString("_tim", strconv.FormatInt(now, 10))
	ctrl.setString("_exp", strconv.FormatInt(now+60, 10))
	if c.nonce != nil {
		ctrl.setRaw("_nonce", c.nonce)
	}
	msg.setDict("_ctrl", ctrl)
	payload := newDict()
	for k, v := range data {
		payload.setString(k, v)
	}
	msg.setDict("_data", payload)
	body, err := signDict(msg, c.secret, c.cfg.Algorithm)
	if err != nil {
		return nil, err
	}
	return frameMessage(body), nil
}

func (c *Client) command(ctx context.Context, data map[string]string) (*dict, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("%w: not connected to RNDC server", ErrConnection)
	}
	frame, err := c.prepare(data)
	if err != nil {
		return nil, err
	}
	deadline, ok := ctx.Deadline()
	if !ok && c.cfg.Timeout > 0 {
		deadline = time.Now().Add(c.cfg.Timeout)
	}
	if !deadline.IsZero() {
		_ = c.conn.SetDeadline(deadline)
		defer func() { _ = c.conn.SetDeadline(time.Time{}) }()
	}
	n, err := c.conn.Write(frame)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConnection, err)
	}
	if n != len(frame) {
		return nil, fmt.Errorf("%w: failed to send complete message", ErrConnection)
	}
	body, err := readFrame(c.conn)
	if err != nil {
		return nil, err
	}
	return verifyBody(c.secret, c.cfg.Algorithm, body, c.nonce)
}

func (c *Client) commandWithRetry(ctx context.Context, data map[string]string) (*dict, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.ensureConn(ctx); err != nil {
		return nil, err
	}
	resp, err := c.command(ctx, data)
	if err == nil {
		return resp, nil
	}
	if !errors.Is(err, ErrConnection) {
		return nil, err
	}
	c.closeLocked()
	if err := c.connect(ctx); err != nil {
		return nil, err
	}
	return c.command(ctx, data)
}

// Call sends an RNDC command string (for example "status" or "reload zone example.com").
func (c *Client) Call(ctx context.Context, command string) (Response, error) {
	resp, err := c.commandWithRetry(ctx, map[string]string{"type": command})
	if err != nil {
		return nil, err
	}
	data := resp.getDict("_data")
	out := Response{}
	if data == nil {
		return out, nil
	}
	for _, k := range data.keys {
		v := data.vals[k]
		if v.dict != nil {
			continue
		}
		out[k] = string(v.raw)
	}
	return out, nil
}

// ZoneOption configures AddZone, DelZone, and Notify.
type ZoneOption func(*zoneOpts)

type zoneOpts struct {
	class    dns.Class
	view     string
	template string
	clean    bool
}

func defaultZoneOpts() zoneOpts {
	return zoneOpts{class: dns.ClassINET, template: "primary"}
}

// WithClass sets the DNS class (default dns.ClassINET).
func WithClass(class dns.Class) ZoneOption {
	return func(o *zoneOpts) { o.class = class }
}

// WithView sets the BIND view name.
func WithView(view string) ZoneOption {
	return func(o *zoneOpts) { o.view = view }
}

// WithTemplate sets the rndc addzone template name (default "primary").
func WithTemplate(template string) ZoneOption {
	return func(o *zoneOpts) { o.template = template }
}

// WithClean requests `delzone -clean`.
func WithClean() ZoneOption {
	return func(o *zoneOpts) { o.clean = true }
}

func applyZoneOpts(opts []ZoneOption) zoneOpts {
	o := defaultZoneOpts()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func checkZoneName(name string) error {
	if _, ok := dns.IsDomainName(name); !ok {
		return fmt.Errorf("%w: %s", ErrInvalidZoneName, name)
	}
	return nil
}

func className(c dns.Class) string {
	s := dns.Class(c).String()
	if s == "" {
		return "IN"
	}
	return s
}

// AddZone issues `addzone` using an optional template.
func (c *Client) AddZone(ctx context.Context, name string, opts ...ZoneOption) error {
	if err := checkZoneName(name); err != nil {
		return err
	}
	o := applyZoneOpts(opts)
	view := o.view
	cmd := fmt.Sprintf("addzone %s %s %s {template %s;};", name, className(o.class), view, o.template)
	result, err := c.Call(ctx, cmd)
	if err != nil {
		return err
	}
	if result.ResultCode() == 16 && result.Err() == "already exists" {
		return fmt.Errorf("%w: zone %s already exists", ErrZoneAlreadyExists, name)
	}
	return nil
}

// DelZone issues `delzone`.
func (c *Client) DelZone(ctx context.Context, name string, opts ...ZoneOption) error {
	if err := checkZoneName(name); err != nil {
		return err
	}
	o := applyZoneOpts(opts)
	suffix := fmt.Sprintf("%s %s %s", name, className(o.class), o.view)
	cmd := "delzone " + suffix
	if o.clean {
		cmd = "delzone -clean " + suffix
	}
	result, err := c.Call(ctx, cmd)
	if err != nil {
		return err
	}
	if result.ResultCode() == 20 && result.Err() == "not found" {
		return fmt.Errorf("%w: zone %s not found", ErrZoneNotFound, name)
	}
	return nil
}

// SetTraceLevel sets the named debug trace level (0–99).
func (c *Client) SetTraceLevel(ctx context.Context, level int) error {
	if level < 0 || level > 99 {
		return fmt.Errorf("trace level must be an integer between 0 and 99")
	}
	_, err := c.Call(ctx, fmt.Sprintf("trace %d", level))
	return err
}

// Notify asks named to send NOTIFY for a zone.
// The command is `notify zone [class [view]]`.
func (c *Client) Notify(ctx context.Context, zone string, opts ...ZoneOption) error {
	if err := checkZoneName(zone); err != nil {
		return err
	}
	o := applyZoneOpts(opts)
	cmd := fmt.Sprintf("notify %s %s", zone, className(o.class))
	if o.view != "" {
		cmd = fmt.Sprintf("notify %s %s %s", zone, className(o.class), o.view)
	}
	result, err := c.Call(ctx, cmd)
	if err != nil {
		return err
	}
	if result.ResultCode() == 20 && result.Err() == "not found" {
		return fmt.Errorf("%w: zone %s not found", ErrZoneNotFound, zone)
	}
	return nil
}

// Status runs `status` and parses the text response.
func (c *Client) Status(ctx context.Context) (*Status, error) {
	resp, err := c.Call(ctx, "status")
	if err != nil {
		return nil, err
	}
	return ParseStatus(resp.Text())
}
