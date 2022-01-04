package net

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/fatedier/kcp-go"
	"golang.org/x/net/websocket"
)

type dialOptions struct {
	proxyURL string
	protocol string

	tlsConfig *tls.Config

	disableCustomTLSHeadByte bool
	customTLSHeaderByte      byte

	websocketPath string

	laddr string // only use ip, port is random

	DialContext func(ctx context.Context, protocol, addr string) (net.Conn, error)
}

type DialOption interface {
	apply(*dialOptions)
}

type funcDialOption struct {
	f func(*dialOptions)
}

func (fdo *funcDialOption) apply(do *dialOptions) {
	fdo.f(do)
}

func newFuncDialOption(f func(*dialOptions)) *funcDialOption {
	return &funcDialOption{
		f: f,
	}
}

func defaultDialOptions() dialOptions {
	return dialOptions{
		protocol: "tcp",
	}
}

func WithProxyURL(proxyURL string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.proxyURL = proxyURL
	})
}

func WithTLSConfig(tlsConfig *tls.Config) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.tlsConfig = tlsConfig
	})
}

func WithDisableCustomTLSHeadByte(disableCustomTLSHeadByte bool) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.disableCustomTLSHeadByte = disableCustomTLSHeadByte
	})
}

func WithProtocol(protocol string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.protocol = protocol
	})
}

func WithLocalAddr(laddr string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.laddr = laddr
	})
}

func WithCustomTLSHeaderByte(customTLSHeaderByte byte) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.customTLSHeaderByte = customTLSHeaderByte
	})
}

func WithWebSocketPath(websocketPath string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.websocketPath = websocketPath
	})
}

func WithDialContext(dialContext func(ctx context.Context, protocol, addr string) (net.Conn, error)) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.DialContext = dialContext
	})
}

func DialWithOptions(addr string, opts ...DialOption) (c net.Conn, err error) {
	return DialContextWithOptions(context.Background(), addr, opts...)
}

func DialContextWithOptions(ctx context.Context, addr string, opts ...DialOption) (c net.Conn, err error) {
	op := defaultDialOptions()

	for _, opt := range opts {
		opt.apply(&op)
	}

	d := NewDialer(op)

	return d.DialContext(ctx, addr)
}

type Dialer struct {
	op dialOptions

	dialer *net.Dialer
}

func NewDialer(ops ...dialOptions) *Dialer {
	return &Dialer{}
}

func (d *Dialer) Dial(addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), addr)
}

func (d *Dialer) DialContext(ctx context.Context, addr string) (c net.Conn, err error) {
	if d.op.DialContext != nil {
		return d.op.DialContext(ctx, d.op.protocol, addr)
	}

	d.dialer = &net.Dialer{}

	if d.op.laddr != "" {
		if tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:%v", d.op.laddr, 0)); err == nil {
			d.dialer = &net.Dialer{
				LocalAddr: tcpAddr,
			}
		}
	}

	if d.op.proxyURL == "" {
		c, err = d.connectServer(ctx, addr)
	} else {
		c, err = d.connectServerByProxy(ctx, addr)
	}
	if err != nil {
		return nil, err
	}

	if d.op.tlsConfig == nil {
		return
	}
	c = d.wrapTLSClientConn(c)
	return
}

func (d *Dialer) connectServer(ctx context.Context, addr string) (c net.Conn, err error) {
	switch d.op.protocol {
	case "tcp":
		return d.dialer.DialContext(ctx, "tcp", addr)
	case "kcp":
		return d.dialKCPServer(addr)
	case "websocket":
		return d.dialWebsocketServer(addr)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", d.op.protocol)
	}
}

func (d *Dialer) connectServerByProxy(ctx context.Context, addr string) (c net.Conn, err error) {
	switch d.op.protocol {
	case "tcp":
		return d.dialTcpByProxy(ctx, addr)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s when connecting by proxy", d.op.protocol)
	}
}

func (d *Dialer) dialKCPServer(addr string) (c net.Conn, err error) {
	kcpConn, errRet := kcp.DialWithOptions(addr, nil, 10, 3)
	if errRet != nil {
		err = errRet
		return
	}
	kcpConn.SetStreamMode(true)
	kcpConn.SetWriteDelay(true)
	kcpConn.SetNoDelay(1, 20, 2, 1)
	kcpConn.SetWindowSize(128, 512)
	kcpConn.SetMtu(1350)
	kcpConn.SetACKNoDelay(false)
	kcpConn.SetReadBuffer(4194304)
	kcpConn.SetWriteBuffer(4194304)
	c = kcpConn
	return
}

// addr: domain:port
func (d *Dialer) dialWebsocketServer(addr string) (net.Conn, error) {
	addr = "ws://" + addr + d.op.websocketPath
	uri, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	origin := "http://" + uri.Host
	cfg, err := websocket.NewConfig(addr, origin)
	if err != nil {
		return nil, err
	}

	cfg.Dialer = d.dialer
	cfg.Dialer.Timeout = 10 * time.Second

	conn, err := websocket.DialConfig(cfg)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (d *Dialer) wrapTLSClientConn(c net.Conn) (out net.Conn) {
	if !d.op.disableCustomTLSHeadByte {
		c.Write([]byte{byte(d.op.customTLSHeaderByte)})
	}
	out = tls.Client(c, d.op.tlsConfig)
	return
}
