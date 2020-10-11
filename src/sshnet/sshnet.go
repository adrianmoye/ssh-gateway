package sshnet

import (
	Log "log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Debug make true to log debug messages
type Debug bool

// Println a wrapper for log.Println
func (d Debug) Println(v ...interface{}) {
	if d {
		Log.Println(v...)
	}
}

var debug Debug = false

// Addr local sshnet address type
type Addr struct {
	addr string
}

// Conn sshnet Conn type, wraps an ssh connection/channel in a net.Conn compatible interface
type Conn struct {
	in            chan []byte
	out           chan []byte
	readNextChunk []byte
	sshConn       *ssh.ServerConn
	client        ssh.Channel

	reader copyDeadline
	writer copyDeadline

	localAddr  Addr
	remoteAddr Addr
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

// Network returns address in compliance with net.Conn interface
func (a Addr) Network() string {
	return a.addr
}

// String returns address in compliance with net.Conn interface
func (a Addr) String() string {
	return a.addr
}

// Read data in compliance with net.Conn interface
func (c *Conn) Read(retBuf []byte) (int, error) {
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

		}

		debug.Println("Read called else len(c.readNextChunk) > len(retBuf)", len(retBuf), len(c.readNextChunk))
		// otherwise just copy the data to the return
		copy(retBuf, c.readNextChunk)
		bytesWrittern := len(c.readNextChunk)
		c.readNextChunk = []byte{}
		return bytesWrittern, nil

	}
	c.reader.Timeout()

	debug.Println("Read called reading:", len(retBuf))
	select {
	case buff, ok := <-c.in:

		debug.Println("Read called read status, len:", ok, len(buff))
		if !ok {
			debug.Println("Read called not ok:", len(buff))
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

		}

		// otherwise just copy the data to the return
		debug.Println("Read called read2:", len(retBuf))
		copy(retBuf, buff)
		c.reader.Finish()
		return len(buff), nil

	case <-c.reader.SigTimout:

		debug.Println("Read timeout")
		c.reader.Finish()
		return 0, os.ErrDeadlineExceeded
	}
}

// Write data in compliance with net.Conn interface
func (c *Conn) Write(b []byte) (int, error) {

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

// Close the connection
func (c *Conn) Close() error {

	debug.Println("Close called")
	if c.out != nil {
		close(c.out)
	}
	c.client.Close()
	return nil
}

// LocalAddr in compliance with net.Conn interface
func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

// RemoteAddr in compliance with net.Conn interface
func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

// SetDeadline in compliance with net.Conn interface
func (c *Conn) SetDeadline(t time.Time) error {

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

// SetReadDeadline in compliance with net.Conn interface
func (c *Conn) SetReadDeadline(t time.Time) error {

	debug.Println("setdreadeadline called", t)
	c.reader.Deadline = t
	c.reader.Timeout()
	return nil
}

// SetWriteDeadline in compliance with net.Conn interface
func (c *Conn) SetWriteDeadline(t time.Time) error {

	debug.Println("setwritedeadline called", t)
	c.writer.Deadline = t
	c.writer.Timeout()
	return nil
}

func (c *Conn) bufferedReader() {
	//c.in = make(chan []byte, 64)

	buff := make([]byte, 1500)
	for {
		sendSize, err := c.client.Read(buff)
		send := make([]byte, sendSize)
		n := copy(send, buff)

		debug.Println("buffered reader:", len(send), sendSize, n)
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

func (c *Conn) buffereWriter() {
	//c.out = make(chan []byte, 64)

	for {
		buff, ok := <-c.out

		if !ok {
			debug.Println("bufferedWrite client not ok:", ok)
			//c.client.Close()
			return
		}

		debug.Println("buffered writer received ", len(buff))
		n, err := c.client.Write(buff)

		debug.Println("buffered writer write ", len(buff), n)
		if err != nil {
			debug.Println("bufferedWrite client error", err)
			return
		}
	}
}

// NewConn takes the ssh connection/channel and wraps them in a Conn
func NewConn(sshConn *ssh.ServerConn, client ssh.Channel) Conn {
	var conn Conn

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

// Listener the public structure of the sshnet listener
type Listener struct {
	connQueue chan *Conn
	addr      Addr
}

// Listen returns the listener data structure
func Listen() (*Listener, error) {

	listener := &Listener{}
	listener.connQueue = make(chan *Conn)

	return listener, nil
}

// Accept connections from the ssh channel connection queue
func (l *Listener) Accept() (net.Conn, error) {

	conn, _ := <-l.connQueue

	return conn, nil
}

// Close unimplemented
func (l *Listener) Close() error {

	return nil
}

// Addr returns the address
func (l *Listener) Addr() net.Addr {
	return l.addr
}

// Dialer connects an ssh channel for a connection to the listener
func (l *Listener) Dialer(sshConn *ssh.ServerConn, client ssh.Channel) {
	conn := NewConn(sshConn, client)
	l.connQueue <- &conn
}
