package distributed

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
)

// BackendType enumerates supported transports.
type BackendType string

const (
	BackendRedis BackendType = "redis"
	BackendNATS  BackendType = "nats"
)

// TransportConfig holds configuration for distributed transport.
type TransportConfig struct {
	Backend           BackendType
	RedisURL          string
	NATSURL           string
	TLSCert           string
	TLSKey            string
	TLSCA             string
	CommandChannel    string
	ResultChannel     string
	HeartbeatChannel  string
	HeartbeatInterval time.Duration
	DialTimeout       time.Duration
}

// CommandEnvelope wraps outbound commands to workers.
type CommandEnvelope struct {
	ID        string            `json:"id"`
	Target    string            `json:"target"`
	Command   string            `json:"command"`
	Payload   []byte            `json:"payload"`
	Priority  int               `json:"priority"`
	Deadline  time.Time         `json:"deadline"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// ResultEnvelope captures worker responses.
type ResultEnvelope struct {
	CommandID string            `json:"command_id"`
	WorkerID  string            `json:"worker_id"`
	Success   bool              `json:"success"`
	Output    []byte            `json:"output"`
	Error     string            `json:"error"`
	Metadata  map[string]string `json:"metadata"`
	Finished  time.Time         `json:"finished"`
}

// Heartbeat signal emitted by workers.
type Heartbeat struct {
	WorkerID     string            `json:"worker_id"`
	Capabilities []string          `json:"capabilities"`
	Metadata     map[string]string `json:"metadata"`
	Timestamp    time.Time         `json:"timestamp"`
}

// Transport abstracts message distribution.
type Transport interface {
	PublishCommand(ctx context.Context, cmd CommandEnvelope) error
	SubscribeCommands(ctx context.Context) (<-chan CommandEnvelope, func(), error)
	PublishResult(ctx context.Context, res ResultEnvelope) error
	SubscribeResults(ctx context.Context) (<-chan ResultEnvelope, func(), error)
	PublishHeartbeat(ctx context.Context, hb Heartbeat) error
	SubscribeHeartbeats(ctx context.Context) (<-chan Heartbeat, func(), error)
	Close() error
}

// NewTransport selects backend based on config.
func NewTransport(cfg TransportConfig) (Transport, error) {
	switch cfg.Backend {
	case BackendRedis:
		return newRedisTransport(cfg)
	case BackendNATS:
		return newNATSTransport(cfg)
	default:
		return nil, fmt.Errorf("unsupported backend: %s", cfg.Backend)
	}
}

// redisTransport implements Transport via Redis Pub/Sub.
type redisTransport struct {
	cfg       TransportConfig
	client    *redis.Client
	closeOnce sync.Once
}

func newRedisTransport(cfg TransportConfig) (Transport, error) {
	opts, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		return nil, err
	}
	if cfg.DialTimeout > 0 {
		opts.DialTimeout = cfg.DialTimeout
	}
	client := redis.NewClient(opts)
	return &redisTransport{cfg: cfg, client: client}, nil
}

func (r *redisTransport) PublishCommand(ctx context.Context, cmd CommandEnvelope) error {
	return r.client.Publish(ctx, channelName(r.cfg.CommandChannel, "commands"), marshal(cmd)).Err()
}

func (r *redisTransport) SubscribeCommands(ctx context.Context) (<-chan CommandEnvelope, func(), error) {
	ch := make(chan CommandEnvelope, 16)
	sub := r.client.Subscribe(ctx, channelName(r.cfg.CommandChannel, "commands"))
	go func() {
		for msg := range sub.Channel() {
			var cmd CommandEnvelope
			if err := unmarshal([]byte(msg.Payload), &cmd); err == nil {
				ch <- cmd
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Close() }
	return ch, cancel, nil
}

func (r *redisTransport) PublishResult(ctx context.Context, res ResultEnvelope) error {
	return r.client.Publish(ctx, channelName(r.cfg.ResultChannel, "results"), marshal(res)).Err()
}

func (r *redisTransport) SubscribeResults(ctx context.Context) (<-chan ResultEnvelope, func(), error) {
	ch := make(chan ResultEnvelope, 16)
	sub := r.client.Subscribe(ctx, channelName(r.cfg.ResultChannel, "results"))
	go func() {
		for msg := range sub.Channel() {
			var res ResultEnvelope
			if err := unmarshal([]byte(msg.Payload), &res); err == nil {
				ch <- res
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Close() }
	return ch, cancel, nil
}

func (r *redisTransport) PublishHeartbeat(ctx context.Context, hb Heartbeat) error {
	return r.client.Publish(ctx, channelName(r.cfg.HeartbeatChannel, "heartbeat"), marshal(hb)).Err()
}

func (r *redisTransport) SubscribeHeartbeats(ctx context.Context) (<-chan Heartbeat, func(), error) {
	ch := make(chan Heartbeat, 16)
	sub := r.client.Subscribe(ctx, channelName(r.cfg.HeartbeatChannel, "heartbeat"))
	go func() {
		for msg := range sub.Channel() {
			var hb Heartbeat
			if err := unmarshal([]byte(msg.Payload), &hb); err == nil {
				ch <- hb
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Close() }
	return ch, cancel, nil
}

func (r *redisTransport) Close() error {
	var err error
	r.closeOnce.Do(func() { err = r.client.Close() })
	return err
}

// natsTransport implements Transport via NATS subjects.
type natsTransport struct {
	cfg       TransportConfig
	conn      *nats.Conn
	closeOnce sync.Once
}

func newNATSTransport(cfg TransportConfig) (Transport, error) {
	nc, err := nats.Connect(cfg.NATSURL, nats.MaxReconnects(-1), nats.Secure(&tls.Config{InsecureSkipVerify: cfg.TLSCA == ""}))
	if err != nil {
		return nil, err
	}
	return &natsTransport{cfg: cfg, conn: nc}, nil
}

func (n *natsTransport) PublishCommand(ctx context.Context, cmd CommandEnvelope) error {
	return n.conn.Publish(channelName(n.cfg.CommandChannel, "commands"), marshal(cmd))
}

func (n *natsTransport) SubscribeCommands(ctx context.Context) (<-chan CommandEnvelope, func(), error) {
	ch := make(chan CommandEnvelope, 16)
	msgCh := make(chan *nats.Msg, 64)
	sub, err := n.conn.ChanSubscribe(channelName(n.cfg.CommandChannel, "commands"), msgCh)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		for msg := range msgCh {
			var cmd CommandEnvelope
			if err := unmarshal(msg.Data, &cmd); err == nil {
				ch <- cmd
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Unsubscribe() }
	return ch, cancel, nil
}

func (n *natsTransport) PublishResult(ctx context.Context, res ResultEnvelope) error {
	return n.conn.Publish(channelName(n.cfg.ResultChannel, "results"), marshal(res))
}

func (n *natsTransport) SubscribeResults(ctx context.Context) (<-chan ResultEnvelope, func(), error) {
	ch := make(chan ResultEnvelope, 16)
	msgCh := make(chan *nats.Msg, 64)
	sub, err := n.conn.ChanSubscribe(channelName(n.cfg.ResultChannel, "results"), msgCh)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		for msg := range msgCh {
			var res ResultEnvelope
			if err := unmarshal(msg.Data, &res); err == nil {
				ch <- res
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Unsubscribe() }
	return ch, cancel, nil
}

func (n *natsTransport) PublishHeartbeat(ctx context.Context, hb Heartbeat) error {
	return n.conn.Publish(channelName(n.cfg.HeartbeatChannel, "heartbeat"), marshal(hb))
}

func (n *natsTransport) SubscribeHeartbeats(ctx context.Context) (<-chan Heartbeat, func(), error) {
	ch := make(chan Heartbeat, 16)
	msgCh := make(chan *nats.Msg, 64)
	sub, err := n.conn.ChanSubscribe(channelName(n.cfg.HeartbeatChannel, "heartbeat"), msgCh)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		for msg := range msgCh {
			var hb Heartbeat
			if err := unmarshal(msg.Data, &hb); err == nil {
				ch <- hb
			}
		}
		close(ch)
	}()
	cancel := func() { _ = sub.Unsubscribe() }
	return ch, cancel, nil
}

func (n *natsTransport) Close() error {
	n.closeOnce.Do(func() { n.conn.Drain(); n.conn.Close() })
	return nil
}

// Helpers

func channelName(base, suffix string) string {
	if base == "" {
		base = "attack"
	}
	return fmt.Sprintf("%s.%s", base, suffix)
}

func marshal(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func unmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
