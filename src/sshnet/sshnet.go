package sshnet

import (
	Log "log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type Debug bool

func (d Debug) Println(v ...interface{}) {
	if d {
		Log.Println(v...)
	}
}

var debug Debug = false

type SSHNetAddr struct {
	addr string
}

type copyDeadline struct {
	// the time deadlines for the read and write timers
	Deadline time.Time
	// the timer that will send the timeout signal
	// to the readers and writers
	Timer *time.Timer

	// the channels that will be used to signal the timeout
	SigTimout chan bool
}

func (c copyDeadline) Timeout() {
	debug.Println("Timeout value:", c.Deadline)
	if c.Timer != nil && !c.Timer.Stop() {
		<-c.Timer.C
	}

	zero := time.Time{}
	if c.Deadline != zero {

		duration := c.Deadline.Sub(time.Now())
		c.Timer = time.AfterFunc(duration, func() {
			debug.Println("Timed out")
			c.SigTimout <- true
		})
	}
}
func (c copyDeadline) Finish() {
	debug.Println("Finish called")
	if c.Timer != nil && !c.Timer.Stop() {
		<-c.Timer.C
	}
}

func newCopyDeadline() copyDeadline {
	debug.Println("newCopyDeadline called")
	var c copyDeadline
	c.Deadline = time.Time{}
	c.SigTimout = make(chan bool)
	return c
}

type SSHNetConn struct {
	in            chan []byte
	out           chan []byte
	readNextChunk []byte
	sshConn       *ssh.ServerConn
	client        ssh.Channel

	reader copyDeadline
	writer copyDeadline

	localAddr  SSHNetAddr
	remoteAddr SSHNetAddr
}

func (a SSHNetAddr) Network() string {
	return "SSHNet"
}

func (a SSHNetAddr) String() string {
	return a.addr
}

func (c *SSHNetConn) Read(retBuf []byte) (int, error) {
	debug.Println("Read called retlen:", len(retBuf))
	//nextZero := []byte{}
	if c.readNextChunk != nil && len(c.readNextChunk) > 0 {

		debug.Println("Read called readNextChunk != nil:", len(retBuf))
		// if the return buffer is too small for the data,
		// snip it up and put the rest in the next chunk
		if len(c.readNextChunk) > len(retBuf) {
			debug.Println("Read called len(c.readNextChunk) > len(retBuf)", len(retBuf))
			copy(retBuf, c.readNextChunk[:len(retBuf)])

			c.readNextChunk = c.readNextChunk[len(retBuf):]

			return len(retBuf), nil

		} else {
			debug.Println("Read called else len(c.readNextChunk) > len(retBuf)", len(retBuf), len(c.readNextChunk))
			// otherwise just copy the data to the return
			copy(retBuf, c.readNextChunk)
			bytesWrittern := len(c.readNextChunk)
			c.readNextChunk = []byte{}
			return bytesWrittern, nil
		}
	}
	c.reader.Timeout()

	debug.Println("Read called reading:", len(retBuf))
	select {
	case buff, ok := <-c.in:

		debug.Println("Read called read status, len:", ok, len(buff))
		if !ok {
			debug.Println("Read called notok:", len(buff))
			c.reader.Finish()
			return 0, os.ErrClosed

		}

		// if the return buffer is too small for the data,
		// snip it up and put the rest in the next chunk
		if len(buff) > len(retBuf) {
			debug.Println("Read called read1:", len(retBuf))
			copy(retBuf, buff[:len(retBuf)])
			c.readNextChunk = buff[len(retBuf):]
			c.reader.Finish()
			return len(retBuf), nil

		} else {
			// otherwise just copy the data to the return
			debug.Println("Read called read2:", len(retBuf))
			copy(retBuf, buff)
			c.reader.Finish()
			return len(buff), nil
		}
		//copy(b, buff)

		debug.Println("Read finished bytes: ", len(buff))
		c.reader.Finish()
		return len(buff), nil
	case <-c.reader.SigTimout:

		debug.Println("Read timeout")
		c.reader.Finish()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *SSHNetConn) Write(b []byte) (int, error) {

	debug.Println("Write called")
	c.writer.Timeout()
	buff := make([]byte, len(b))
	copy(buff, b)
	select {
	case c.out <- buff:

		debug.Println("Write finished bytes:", len(buff))
		c.writer.Finish()
		return len(buff), nil
	case <-c.writer.SigTimout:

		debug.Println("Write timeout called")
		c.writer.Finish()
		return 0, os.ErrDeadlineExceeded
	}
}

func (c *SSHNetConn) Close() error {

	debug.Println("Close called")
	if c.out != nil {
		close(c.out)
	}
	c.client.Close()
	return nil
}

func (c *SSHNetConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *SSHNetConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *SSHNetConn) SetDeadline(t time.Time) error {

	debug.Println("setdeadline called", t)
	err := c.SetReadDeadline(t)
	if err != nil {
		return err
	}
	err = c.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return nil
}

func (c *SSHNetConn) SetReadDeadline(t time.Time) error {

	debug.Println("setdreadeadline called", t)
	c.reader.Deadline = t
	c.reader.Timeout()
	return nil
}

func (c *SSHNetConn) SetWriteDeadline(t time.Time) error {

	debug.Println("setwritedeadline called", t)
	c.writer.Deadline = t
	c.writer.Timeout()
	return nil
}

func (c *SSHNetConn) bufferedReader() {
	//c.in = make(chan []byte, 64)

	buff := make([]byte, 1500)
	for {
		sendSize, err := c.client.Read(buff)
		send := make([]byte, sendSize)
		n := copy(send, buff)

		debug.Println("buffered reader [%d][%d]", len(send), sendSize, n)
		if err != nil {
			debug.Println("bufferedRead client error:", err)

			if c.in != nil {
				close(c.in)
			}
			return
		}
		c.in <- send
	}
}

func (c *SSHNetConn) buffereWriter() {
	//c.out = make(chan []byte, 64)

	for {
		buff, ok := <-c.out

		if !ok {
			debug.Println("bufferedWrite client not ok:", ok)
			//c.client.Close()
			return
		}

		debug.Println("buffered writer received [%d][%d]", len(buff))
		n, err := c.client.Write(buff)

		debug.Println("buffered writer write [%d][%d]", len(buff), n)
		if err != nil {
			debug.Println("bufferedWrite client error:", err)
			return
		}
	}
}

func NewSSHNetConn(sshConn *ssh.ServerConn, client ssh.Channel) SSHNetConn {
	var conn SSHNetConn

	conn.in = make(chan []byte, 1)
	conn.out = make(chan []byte, 1)
	conn.sshConn = sshConn
	conn.client = client

	conn.remoteAddr.addr = conn.sshConn.User() + "@" + conn.sshConn.RemoteAddr().String()

	conn.reader = newCopyDeadline()
	conn.writer = newCopyDeadline()

	go conn.bufferedReader()
	go conn.buffereWriter()

	return conn
}

type SSHNetListener struct {
	connQueue chan *SSHNetConn
	addr      SSHNetAddr
}

func ListenSSHNet() (*SSHNetListener, error) {

	listener := &SSHNetListener{}
	listener.connQueue = make(chan *SSHNetConn)

	return listener, nil
}

func (l *SSHNetListener) Accept() (net.Conn, error) {

	conn, _ := <-l.connQueue

	return conn, nil
}

func (l *SSHNetListener) Close() error {

	return nil
}

func (l *SSHNetListener) Addr() net.Addr {
	return l.addr
}

func (l *SSHNetListener) Dialer(sshConn *ssh.ServerConn, client ssh.Channel) {
	conn := NewSSHNetConn(sshConn, client)
	l.connQueue <- &conn
}
