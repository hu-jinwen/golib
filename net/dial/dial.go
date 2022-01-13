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
	"context"
	"fmt"
	"net"
	"sort"

	"github.com/fatedier/kcp-go"
)

func DialWithOptions(addr string, opts ...DialOption) (c net.Conn, err error) {
	return DialContextWithOptions(context.Background(), addr, opts...)
}

func DialContextWithOptions(ctx context.Context, addr string, opts ...DialOption) (c net.Conn, err error) {
	op := defaultDialOptions()

	for _, opt := range opts {
		opt.apply(&op)
	}

	switch op.proxyScheme {
	case "socks5":
		op.dialAfterHook = append(op.dialAfterHook, newSocks5DialAfterHook(addr, op))
	case "http":
		op.dialAfterHook = append(op.dialAfterHook, newHTTPProxyAfterHook(addr, op))
	case "ntlm":
		op.dialAfterHook = append(op.dialAfterHook, newNTLMHTTPProxyAfterHook(addr, op))
	}

	if op.websocketPath != "" {
		op.dialAfterHook = append(op.dialAfterHook, newWebsocketAfterHook(addr, op))
	}
	if op.tlsConfig != nil {
		op.dialAfterHook = append(op.dialAfterHook, newTLSDialAfterHook(addr, op))
	}

	// dial real connection
	if op.dialer != nil {
		c, err = op.dialer(ctx, addr)
	} else {
		if op.proxyURL != "" {
			addr = op.proxyAddr
		}
		c, err = dial(ctx, addr, op)
	}

	if err != nil {
		return nil, err
	}

	sort.Slice(op.dialAfterHook, func(i, j int) bool {
		return op.dialAfterHook[i].Priority < op.dialAfterHook[j].Priority
	})

	for _, hook := range op.dialAfterHook {
		c, err = hook.Hook(c)
		if err != nil {
			return nil, err
		}
	}

	return
}

func dial(ctx context.Context, addr string, op dialOptions) (c net.Conn, err error) {
	switch op.protocol {
	case "tcp":
		dialer := &net.Dialer{}
		if tcpAddr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%v:0", op.laddr)); err == nil {
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
