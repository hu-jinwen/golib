// Copyright 2018 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dial

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/go-ntlmssp"
	"golang.org/x/net/proxy"
	"golang.org/x/net/websocket"
)

type dialOptions struct {
	proxyURL string

	proxyScheme string
	proxyAddr   string // if proxyURL not empty, proxyAddr will be generate
	proxyAuth   *ProxyAuth

	protocol string

	tlsConfig *tls.Config

	websocketPath string

	laddr string // only use ip, port is random

	dialer func(ctx context.Context, addr string) (c net.Conn, err error)

	dialAfterHook  []dialHook
	dialBeforeHook []dialHook
}

type dialHook struct {
	Priority uint // smaller value will be executed first
	Hook     func(c net.Conn) (net.Conn, error)
}

func newWebsocketAfterHook(addr string, op dialOptions) dialHook {
	return dialHook{
		Priority: 1,
		Hook: func(c net.Conn) (net.Conn, error) {
			return websocketHook(c, addr, op)
		},
	}
}

func newSocks5DialAfterHook(addr string, op dialOptions) dialHook {
	return dialHook{
		Priority: 1,
		Hook: func(c net.Conn) (net.Conn, error) {
			return socks5Hook(c, addr, op)
		},
	}
}

func newHTTPProxyAfterHook(addr string, op dialOptions) dialHook {
	return dialHook{
		Priority: 1,
		Hook: func(c net.Conn) (net.Conn, error) {
			return httpProxyHook(c, addr, op)
		},
	}
}

func newNTLMHTTPProxyAfterHook(addr string, op dialOptions) dialHook {
	return dialHook{
		Priority: 1,
		Hook: func(c net.Conn) (net.Conn, error) {
			return ntlmHTTPProxyHook(c, addr, op)
		},
	}
}

func newTLSDialAfterHook(addr string, op dialOptions) dialHook {
	return dialHook{
		Priority: math.MaxInt32,
		Hook: func(c net.Conn) (net.Conn, error) {
			return tlsHook(c, op)
		},
	}
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
		var proxyUrl *url.URL
		var err error

		if proxyUrl, err = url.Parse(proxyURL); err != nil {
			return
		}

		auth := &ProxyAuth{}
		if proxyUrl.User != nil {
			auth.Enable = true
			auth.Username = proxyUrl.User.Username()
			auth.Passwd, _ = proxyUrl.User.Password()
		}

		do.proxyScheme = proxyUrl.Scheme
		do.proxyAddr = proxyUrl.Host
		do.proxyAuth = auth

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
		do.protocol = protocol
	})
}

func WithLocalAddr(laddr string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.laddr = laddr
	})
}

func WithWebSocketPath(websocketPath string) DialOption {
	return newFuncDialOption(func(do *dialOptions) {
		do.websocketPath = websocketPath
	})
}

type ProxyAuth struct {
	Enable   bool
	Username string
	Passwd   string
}

type funcDialContext func(ctx context.Context, networkd string, addr string) (c net.Conn, err error)

func (fdc funcDialContext) DialContext(ctx context.Context, network string, addr string) (c net.Conn, err error) {
	return fdc(ctx, network, addr)
}

func (fdc funcDialContext) Dial(network string, addr string) (c net.Conn, err error) {
	return fdc(context.Background(), network, addr)
}

func websocketHook(conn net.Conn, addr string, op dialOptions) (net.Conn, error) {
	addr = "ws://" + addr + op.websocketPath
	uri, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}

	origin := "http://" + uri.Host
	cfg, err := websocket.NewConfig(addr, origin)
	if err != nil {
		return nil, err
	}

	return websocket.NewClient(cfg, conn)
}

func socks5Hook(conn net.Conn, addr string, op dialOptions) (c net.Conn, err error) {
	var s5Auth *proxy.Auth
	if op.proxyAuth.Enable {
		s5Auth = &proxy.Auth{
			User:     op.proxyAuth.Username,
			Password: op.proxyAuth.Passwd,
		}
	}

	dialer, err := proxy.SOCKS5("tcp", op.proxyAddr, s5Auth, funcDialContext(func(_ context.Context, network string, addr string) (net.Conn, error) {
		// always return an exist connection
		return conn, nil
	}))

	if err != nil {
		return nil, err
	}

	if c, err = dialer.Dial("tcp", addr); err != nil {
		return
	}
	return
}

func tlsHook(conn net.Conn, op dialOptions) (net.Conn, error) {
	if op.tlsConfig == nil {
		return conn, nil
	}
	return tls.Client(conn, op.tlsConfig), nil
}

func httpProxyHook(conn net.Conn, addr string, op dialOptions) (net.Conn, error) {
	req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
	if err != nil {
		return nil, err
	}
	if op.proxyAuth.Enable {
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(op.proxyAuth.Username+":"+op.proxyAuth.Passwd)))
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.Write(conn)

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DialTcpByHttpProxy error, StatusCode [%d]", resp.StatusCode)
	}

	return conn, nil
}

func ntlmHTTPProxyHook(conn net.Conn, addr string, op dialOptions) (net.Conn, error) {
	req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
	if err != nil {
		return nil, err
	}
	if op.proxyAuth.Enable {
		domain := ""
		_, domain = ntlmssp.GetDomain(op.proxyAuth.Username)
		negotiateMessage, err := ntlmssp.NewNegotiateMessage(domain, "")
		if err != nil {
			return nil, err
		}
		req.Header.Add("Proxy-Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMessage))
	}

	req.Write(conn)
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	if op.proxyAuth.Enable && resp.StatusCode == 407 {
		challenge := resp.Header.Get("Proxy-Authenticate")
		username, _ := ntlmssp.GetDomain(op.proxyAuth.Username)

		if strings.HasPrefix(challenge, "Negotiate ") {
			challengeMessage, err := base64.StdEncoding.DecodeString(challenge[len("Negotiate "):])
			if err != nil {
				return nil, err
			}
			authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, username, op.proxyAuth.Passwd)
			if err != nil {
				return nil, err
			}
			req, err := http.NewRequest("CONNECT", "http://"+addr, nil)
			if err != nil {
				return nil, err
			}

			req.Header.Add("Proxy-Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
			req.Write(conn)
			resp, err = http.ReadResponse(bufio.NewReader(conn), req)
			if err != nil {
				return nil, err
			}
			resp.Body.Close()
		}
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("DialTcpByNTLMHttpProxy error, StatusCode [%d]", resp.StatusCode)
	}

	return conn, nil
}
