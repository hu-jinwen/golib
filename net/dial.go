package net

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	kcp "github.com/fatedier/kcp-go"
	"golang.org/x/net/proxy"
)

type dialOptions struct {
	proxyURL string
	protocol string

	tlsConfig *tls.Config

	laddr string // only use ip, port is random

	dialer        func(context.Context, string) (net.Conn, error)
	dialAfterHook func(context.Context, net.Conn) error
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

func WithProtocol(protocol string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.protocol = strings.ToLower(protocol)
	})
}

func WithLocalAddr(laddr string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.laddr = laddr
	})
}

func WithDialer(f func(context.Context, string) (net.Conn, error)) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.dialer = f
	})
}

func WithDialAfterHook(f func(context.Context, net.Conn) error) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.dialAfterHook = f
	})
}

func defaultDialOptions() dialOptions {
	return dialOptions{
		protocol: "tcp",
	}

}

func Dial(addr string, opts ...DialOption) (c net.Conn, err error) {
	return DialContext(context.Background(), addr, opts...)
}

func DialContext(ctx context.Context, addr string, opts ...DialOption) (c net.Conn, err error) {
	op := defaultDialOptions()

	for _, opt := range opts {
		opt.apply(&op)
	}

	if op.dialer != nil {
		c, err = op.dialer(ctx, addr)
	} else {
		if op.proxyURL == "" {
			c, err = dial(ctx, addr, op)
		} else {
			c, err = dialWithProxy(ctx, addr)
		}
		if err != nil {
			return nil, err
		}
	}

	if op.dialAfterHook != nil {
		op.dialAfterHook(ctx, c)
	}

	if op.tlsConfig != nil {
		c = tls.Client(c, d.op.tlsConfig)
	}
	return
}

func dial(ctx context.Context, addr string, op dialOptions) (c net.Conn, err error) {
	switch op.protocol {
	case "tcp":
		dialer := &net.Dialer{}
		if tcpAddr, err := net.ResolveTCPAddr("tcp", op.laddr); err == nil {
			dialer = &net.Dialer{
				LocalAddr: tcpAddr,
			}
		}
		return dialer.DialContext(ctx, "tcp", addr)
	case "kcp":
		return dialKCPServer(addr)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s", op.protocol)
	}
}

func dialWithProxy(ctx context.Context, addr string, op dialOptions) (c net.Conn, err error) {
	switch op.protocol {
	case "tcp":
		return dialTCPByProxy(ctx, addr)
	default:
		return nil, fmt.Errorf("unsupport protocol: %s when connecting by proxy", d.op.protocol)
	}
}

func dialKCPServer(addr string) (c net.Conn, err error) {
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

func dialTCPByProxy(proxyStr string, addr string) (c net.Conn, err error) {
	if proxyStr == "" {
		return net.Dial("tcp", addr)
	}

	var proxyUrl *url.URL
	if proxyUrl, err = url.Parse(proxyStr); err != nil {
		return
	}

	auth := &ProxyAuth{}
	if proxyUrl.User != nil {
		auth.Enable = true
		auth.Username = proxyUrl.User.Username()
		auth.Passwd, _ = proxyUrl.User.Password()
	}

	switch proxyUrl.Scheme {
	case "http":
		return dialTCPByHttpProxy(proxyUrl.Host, addr, auth)
	case "socks5":
		return dialTCPBySocks5Proxy(proxyUrl.Host, addr, auth)
	default:
		err = fmt.Errorf("Proxy URL scheme must be http or socks5, not [%s]", proxyUrl.Scheme)
		return
	}
}

func dialTCPByHttpProxy(proxyHost string, dstAddr string, auth *ProxyAuth) (c net.Conn, err error) {
	if c, err = net.Dial("tcp", proxyHost); err != nil {
		return
	}

	req, err := http.NewRequest("CONNECT", "http://"+dstAddr, nil)
	if err != nil {
		return
	}
	if auth.Enable {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth.Username+":"+auth.Passwd)))
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Write(c)

	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		err = fmt.Errorf("DialTcpByHttpProxy error, StatusCode [%d]", resp.StatusCode)
		return
	}
	return
}

func dialTCPBySocks5Proxy(proxyHost string, dstAddr string, auth *ProxyAuth) (c net.Conn, err error) {
	var s5Auth *proxy.Auth
	if auth.Enable {
		s5Auth = &proxy.Auth{
			User:     auth.Username,
			Password: auth.Passwd,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", proxyHost, s5Auth, nil)
	if err != nil {
		return nil, err
	}

	if c, err = dialer.Dial("tcp", dstAddr); err != nil {
		return
	}
	return
}
