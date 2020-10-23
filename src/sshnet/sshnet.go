package sshnet

import (
	Log "log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/prometheus/client_golang/prometheus"
)

// Debug make true to log debug messages
type Debug bool

// Println a wrapper for debug.Println
func (d Debug) Println(v ...interface{}) {
	if d {
		Log.Println(v...)
	}
}

var debug Debug = false

// The Metrics that the module produces
type Metrics struct {
	Accept        prometheus.Counter
	Close         prometheus.Counter
	Dialer        prometheus.Counter
	BytesRead     prometheus.Counter
	BytesWrittern prometheus.Counter
}

func newMetrics() (ret Metrics) {
	ret = Metrics{
		Accept: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "netssh",
				Name:      "accept_counter",
				Help:      "Number of accepted connections by listener",
			}),

		BytesRead: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "netssh",
				Name:      "bytesread_counter",
				Help:      "Number of bytes read from the virtual interface",
			}),

		BytesWrittern: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "netssh",
				Name:      "byteswrittern_counter",
				Help:      "Number of bytes writtern from the virtual interface",
			}),

		Close: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "netssh",
				Name:      "close_counter",
				Help:      "Number of connections closed",
			}),

		Dialer: prometheus.NewCounter(
			prometheus.CounterOpts{
				Namespace: "netssh",
				Name:      "dialer_counter",
				Help:      "Number of connections dialed in",
			}),
	}

	prometheus.MustRegister(ret.Accept)
	prometheus.MustRegister(ret.BytesRead)
	prometheus.MustRegister(ret.BytesWrittern)
	prometheus.MustRegister(ret.Close)
	prometheus.MustRegister(ret.Dialer)

	// Add Go module build info.
	prometheus.MustRegister(prometheus.NewBuildInfoCollector())
	return
}

var met Metrics = newMetrics()

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

			met.BytesRead.Add(float64(len(retBuf)))
			return len(retBuf), nil

		}

		debug.Println("Read called else len(c.readNextChunk) > len(retBuf)", len(retBuf), len(c.readNextChunk))
		// otherwise just copy the data to the return
		copy(retBuf, c.readNextChunk)
		bytesWrittern := len(c.readNextChunk)
		c.readNextChunk = []byte{}
		met.BytesRead.Add(float64(bytesWrittern))
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

			met.BytesRead.Add(float64(len(retBuf)))
			return len(retBuf), nil

		}

		// otherwise just copy the data to the return
		debug.Println("Read called read2:", len(retBuf))
		copy(retBuf, buff)
		c.reader.Finish()
		met.BytesRead.Add(float64(len(buff)))
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
		met.BytesWrittern.Add(float64(len(buff)))
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
	//c.in = make(chan []byte, 1)
	//c.reader = newCopyDeadline()

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
	//c.out = make(chan []byte, 1)
	//c.writer = newCopyDeadline()

	for {
		buff, ok := <-c.out

		if !ok {
			debug.Println("bufferedWrite client not ok:", ok)
			//c.client.Close()
			return
		}

		// bug here, what if we don't write all of the buffer :-/ eek sorry
		debug.Println("buffered writer received ", len(buff))
		pos := 0
		for pos < len(buff) {
			n, err := c.client.Write(buff[pos:])
			pos += n
			debug.Println("buffered writer write ", len(buff[pos:]), n)
			if err != nil {
				debug.Println("bufferedWrite client error", err)
				return
			}
		}
	}
}

// NewConn takes the ssh connection/channel and wraps them in a Conn
func NewConn(sshConn *ssh.ServerConn, client ssh.Channel) Conn {
	var c Conn

	c.in = make(chan []byte, 1)
	c.out = make(chan []byte, 1)
	c.sshConn = sshConn
	c.client = client

	c.remoteAddr.addr = c.sshConn.User() + "@" + c.sshConn.RemoteAddr().String()

	c.reader = newCopyDeadline()
	c.writer = newCopyDeadline()

	go c.bufferedReader()
	go c.buffereWriter()

	return c
}

// Listener the public structure of the sshnet listener
type Listener struct {
	connQueue chan *Conn
	closed    bool
	addr      Addr
}

// Listen returns the listener data structure
func Listen(addr string) (*Listener, error) {

	listener := &Listener{}
	listener.closed = false
	listener.addr.addr = addr
	listener.connQueue = make(chan *Conn)

	debug.Println(len(listener.connQueue), cap(listener.connQueue))

	debug.Println("Listening:" + addr)
	return listener, nil
}

// Accept connections from the ssh channel connection queue
func (l *Listener) Accept() (net.Conn, error) {

	debug.Println("accept")
	conn, _ := <-l.connQueue
	met.Accept.Add(1)
	/*
		if err {
			return nil, os.ErrClosed
		}*/

	return conn, nil
}

// Close  the receive listener channel
func (l *Listener) Close() error {

	met.Close.Add(1)
	//l.closed = true
	//close(l.connQueue)
	return nil
}

// Addr returns the address
func (l *Listener) Addr() net.Addr {
	return l.addr
}

// Dialer connects an ssh channel for a connection to the listener
func (l *Listener) Dialer(sshConn *ssh.ServerConn, client ssh.Channel) {
	conn := NewConn(sshConn, client)
	debug.Println("doing put connection on listen queue")
	debug.Println(len(l.connQueue), cap(l.connQueue))
	l.connQueue <- &conn

	met.Dialer.Add(1)

	debug.Println("done put connection on listen queue")
}
