// SPDX-License-Identifier: BSD-2-Clause

package tailnet

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/balajiv113/fd"
	"github.com/containers/gvisor-tap-vsock/pkg/types"
)

// acceptQemu connects each VM that connects to ln, exchanging frames with
// QEMU's stream framing.
func (n *Network) acceptQemu(ctx context.Context, ln net.Listener) error {
	return acceptLoop(ln, func(conn net.Conn) error {
		return n.sw.Accept(ctx, conn, types.QemuProtocol)
	}, n.opts.Bridge.cfg.Logf)
}

// acceptBess connects each VM whose datagram socket is passed over ln with
// SCM_RIGHTS, as the vz and krunkit drivers do.
func (n *Network) acceptBess(ctx context.Context, ln net.Listener) error {
	return acceptLoop(ln, func(conn net.Conn) error {
		uc, ok := conn.(*net.UnixConn)
		if !ok {
			return fmt.Errorf("unexpected connection type %T", conn)
		}
		files, err := fd.Get(uc, 1, []string{"client"})
		if err != nil {
			return fmt.Errorf("receiving the VM socket: %w", err)
		}
		if len(files) != 1 {
			return fmt.Errorf("received %d file descriptors, want 1", len(files))
		}
		vmConn, err := net.FileConn(files[0])
		_ = files[0].Close()
		if err != nil {
			return err
		}
		defer vmConn.Close()
		return n.sw.Accept(ctx, vmConn, types.BessProtocol)
	}, n.opts.Bridge.cfg.Logf)
}

func acceptLoop(ln net.Listener, handle func(net.Conn) error, logf func(string, ...any)) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			if err := handle(conn); err != nil && !errors.Is(err, net.ErrClosed) {
				logf("%s: VM connection closed: %v", ln.Addr(), err)
			}
		}()
	}
}
