// relay-gateway: satu forward proxy lokal (HTTP CONNECT) untuk magpie yang
// memilih upstream di belakangnya: relay Vercel (via MITM terbatas),
// proxy HTTP, SOCKS5, atau direct.
//
// Pemilihan pool lewat Proxy-Authorization (Basic):
//
//	username = "<pool>" atau "<pool>~<sticky-key>", password = cfg.password
//
// Hanya stdlib. Config berupa JSON.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const maxRelayBody = 16 << 20 // body request di-buffer supaya bisa retry ke relay lain

// ---------- config ----------

type UpstreamCfg struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // vercel | http | socks5 | direct
	URL  string `json:"url"`
}

type PoolCfg struct {
	Members      []string `json:"members"`
	Strategy     string   `json:"strategy"` // round_robin | failover | sticky
	MITMHosts    []string `json:"mitm_hosts"`
	CooldownSecs int      `json:"cooldown_secs"`
}

type Config struct {
	Listen    string              `json:"listen"`
	Password  string              `json:"password"`
	CACert    string              `json:"ca_cert"`
	CAKey     string              `json:"ca_key"`
	Upstreams []UpstreamCfg       `json:"upstreams"`
	Pools     map[string]*PoolCfg `json:"pools"`
}

// ---------- runtime types ----------

type up struct {
	UpstreamCfg
	u    *url.URL
	down atomic.Int64 // unix nano sampai kapan di-cooldown
}

type pool struct {
	name     string
	members  []*up
	strategy string
	mitm     map[string]bool
	cooldown time.Duration
}

func (p *pool) mitms(host string) bool { return p.mitm[strings.ToLower(host)] }

type Gateway struct {
	cfg    Config
	pools  map[string]*pool
	ca     *CA
	rr     atomic.Uint64
	client *http.Client
}

// ---------- main ----------

func main() {
	cfgPath := flag.String("config", "config.json", "path ke config JSON")
	flag.Parse()

	raw, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalf("baca config: %v", err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("parse config: %v", err)
	}
	g, err := New(cfg)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	srv := &http.Server{
		Addr:              g.cfg.Listen,
		Handler:           g,
		ReadHeaderTimeout: 30 * time.Second,
	}
	log.Printf("relay-gateway listen %s, CA: %s", g.cfg.Listen, g.cfg.CACert)
	log.Fatal(srv.ListenAndServe())
}

func New(cfg Config) (*Gateway, error) {
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:7890"
	}
	if cfg.CACert == "" {
		cfg.CACert = "ca.pem"
	}
	if cfg.CAKey == "" {
		cfg.CAKey = "ca-key.pem"
	}
	ca, err := loadOrCreateCA(cfg.CACert, cfg.CAKey)
	if err != nil {
		return nil, fmt.Errorf("CA: %w", err)
	}

	ups := map[string]*up{}
	for _, uc := range cfg.Upstreams {
		if uc.Name == "" {
			return nil, errors.New("upstream tanpa name")
		}
		u := &up{UpstreamCfg: uc}
		switch uc.Kind {
		case "direct":
		case "vercel", "http", "socks5":
			pu, err := url.Parse(uc.URL)
			if err != nil || pu.Host == "" {
				return nil, fmt.Errorf("upstream %s: url tidak valid", uc.Name)
			}
			u.u = pu
		default:
			return nil, fmt.Errorf("upstream %s: kind %q tidak dikenal", uc.Name, uc.Kind)
		}
		ups[uc.Name] = u
	}

	pools := map[string]*pool{}
	for name, pc := range cfg.Pools {
		p := &pool{name: name, strategy: pc.Strategy, mitm: map[string]bool{}, cooldown: 30 * time.Second}
		if p.strategy == "" {
			p.strategy = "failover"
		}
		if pc.CooldownSecs > 0 {
			p.cooldown = time.Duration(pc.CooldownSecs) * time.Second
		}
		for _, m := range pc.Members {
			u, ok := ups[m]
			if !ok {
				return nil, fmt.Errorf("pool %s: member %q tidak ada", name, m)
			}
			p.members = append(p.members, u)
		}
		if len(p.members) == 0 {
			return nil, fmt.Errorf("pool %s kosong", name)
		}
		for _, h := range pc.MITMHosts {
			p.mitm[strings.ToLower(h)] = true
		}
		pools[name] = p
	}
	if len(pools) == 0 {
		return nil, errors.New("tidak ada pool")
	}

	tr := &http.Transport{
		ForceAttemptHTTP2:     true,
		DisableCompression:    true, // kita minta identity sendiri ke relay
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 180 * time.Second, // LLM bisa lama sebelum byte pertama
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Gateway{cfg: cfg, pools: pools, ca: ca, client: client}, nil
}

// ---------- entry point ----------

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		if r.URL.Path == "/healthz" {
			io.WriteString(w, "ok\n")
			return
		}
		http.Error(w, "hanya CONNECT yang didukung", http.StatusMethodNotAllowed)
		return
	}
	p, key, ok := g.auth(r)
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Basic realm="relay-gateway"`)
		http.Error(w, "", http.StatusProxyAuthRequired)
		return
	}
	g.handleConnect(w, r, p, key)
}

// auth: username "<pool>" atau "<pool>~<key>"; kosong -> pool "default".
func (g *Gateway) auth(r *http.Request) (*pool, string, bool) {
	user, pass := "", ""
	if h := r.Header.Get("Proxy-Authorization"); h != "" {
		if rest, ok := strings.CutPrefix(h, "Basic "); ok {
			if b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rest)); err == nil {
				user, pass, _ = strings.Cut(string(b), ":")
			}
		}
	}
	if g.cfg.Password != "" && subtle.ConstantTimeCompare([]byte(pass), []byte(g.cfg.Password)) != 1 {
		return nil, "", false
	}
	name, key, _ := strings.Cut(user, "~")
	if name == "" {
		name = "default"
	}
	p, ok := g.pools[name]
	if !ok {
		return nil, "", false
	}
	if key == "" {
		key = name
	}
	return p, key, true
}

func (g *Gateway) candidates(p *pool, key string) []*up {
	n := len(p.members)
	start := 0
	switch p.strategy {
	case "round_robin":
		start = int(g.rr.Add(1) % uint64(n))
	case "sticky":
		h := fnv.New32a()
		h.Write([]byte(key))
		start = int(h.Sum32() % uint32(n))
	}
	now := time.Now().UnixNano()
	var healthy, cooling []*up
	for i := 0; i < n; i++ {
		u := p.members[(start+i)%n]
		if u.down.Load() > now {
			cooling = append(cooling, u)
		} else {
			healthy = append(healthy, u)
		}
	}
	return append(healthy, cooling...)
}

func (p *pool) markDown(u *up) { u.down.Store(time.Now().Add(p.cooldown).UnixNano()) }

func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request, p *pool, key string) {
	hostport := r.Host
	hostname, _, err := net.SplitHostPort(hostport)
	if err != nil {
		hostname = hostport
		hostport = net.JoinHostPort(hostport, "443")
	}
	cands := g.candidates(p, key)

	if p.mitms(hostname) {
		var relays []*up
		for _, u := range cands {
			if u.Kind == "vercel" {
				relays = append(relays, u)
			}
		}
		if len(relays) > 0 {
			g.mitmServe(w, hostname, hostport, relays, p)
			return
		}
	}

	for _, u := range cands {
		if u.Kind == "vercel" {
			continue // relay Vercel tidak bisa tunnel TCP mentah
		}
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		conn, err := u.dial(ctx, hostport)
		cancel()
		if err != nil {
			log.Printf("[%s] dial %s via %s gagal: %v", p.name, hostport, u.Name, err)
			p.markDown(u)
			continue
		}
		client, err := hijack(w)
		if err != nil {
			conn.Close()
			return
		}
		client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		log.Printf("[%s] tunnel %s via %s", p.name, hostport, u.Name)
		pipe(client, conn)
		return
	}
	http.Error(w, "tidak ada upstream yang bisa dipakai", http.StatusBadGateway)
}

// ---------- tunnel helpers ----------

type prefixConn struct {
	net.Conn
	r io.Reader
}

func (p *prefixConn) Read(b []byte) (int, error) { return p.r.Read(b) }

func hijack(w http.ResponseWriter) (net.Conn, error) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, errors.New("hijack tidak didukung")
	}
	c, brw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if n := brw.Reader.Buffered(); n > 0 {
		b, _ := brw.Reader.Peek(n)
		c = &prefixConn{Conn: c, r: io.MultiReader(bytes.NewReader(append([]byte(nil), b...)), c)}
	}
	return c, nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			dst.Close()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	<-done
	a.Close()
	b.Close()
}

// ---------- dial ke upstream ----------

func (u *up) dial(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	switch u.Kind {
	case "direct":
		return d.DialContext(ctx, "tcp", addr)
	case "http":
		return u.dialHTTP(ctx, addr)
	case "socks5":
		return u.dialSOCKS5(ctx, addr)
	}
	return nil, fmt.Errorf("kind %s tidak bisa di-dial", u.Kind)
}

func (u *up) dialHTTP(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", u.u.Host)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	req := "CONNECT " + addr + " HTTP/1.1\r\nHost: " + addr + "\r\n"
	if u.u.User != nil {
		pw, _ := u.u.User.Password()
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(u.u.User.Username()+":"+pw)) + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		c.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		c.Close()
		return nil, fmt.Errorf("upstream CONNECT: %s", resp.Status)
	}
	c.SetDeadline(time.Time{})
	if br.Buffered() > 0 {
		return &prefixConn{Conn: c, r: br}, nil
	}
	return c, nil
}

func (u *up) dialSOCKS5(ctx context.Context, addr string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", u.u.Host)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) { c.Close(); return nil, err }
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	user, pass, hasAuth := "", "", false
	if u.u.User != nil {
		user = u.u.User.Username()
		pass, _ = u.u.User.Password()
		hasAuth = true
	}
	if hasAuth {
		c.Write([]byte{5, 2, 0, 2})
	} else {
		c.Write([]byte{5, 1, 0})
	}
	rb := make([]byte, 2)
	if _, err := io.ReadFull(c, rb); err != nil {
		return fail(err)
	}
	switch {
	case rb[0] != 5:
		return fail(errors.New("socks5: versi salah"))
	case rb[1] == 2 && hasAuth:
		msg := append([]byte{1, byte(len(user))}, user...)
		msg = append(msg, byte(len(pass)))
		msg = append(msg, pass...)
		c.Write(msg)
		if _, err := io.ReadFull(c, rb); err != nil {
			return fail(err)
		}
		if rb[1] != 0 {
			return fail(errors.New("socks5: auth ditolak"))
		}
	case rb[1] != 0:
		return fail(errors.New("socks5: metode auth tidak diterima"))
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fail(err)
	}
	var port uint16
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return fail(err)
	}
	req := []byte{5, 1, 0}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 1)
			req = append(req, v4...)
		} else {
			req = append(req, 4)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	c.Write(req)

	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return fail(err)
	}
	if hdr[1] != 0 {
		return fail(fmt.Errorf("socks5: reply code %d", hdr[1]))
	}
	skip := 0
	switch hdr[3] {
	case 1:
		skip = 4 + 2
	case 4:
		skip = 16 + 2
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(c, l); err != nil {
			return fail(err)
		}
		skip = int(l[0]) + 2
	}
	if _, err := io.CopyN(io.Discard, c, int64(skip)); err != nil {
		return fail(err)
	}
	c.SetDeadline(time.Time{})
	return c, nil
}

// ---------- MITM -> relay Vercel ----------

type oneConnListener struct {
	ch     chan net.Conn
	once   sync.Once
	closed chan struct{}
}

func newOneConnListener(c net.Conn) *oneConnListener {
	l := &oneConnListener{ch: make(chan net.Conn, 1), closed: make(chan struct{})}
	l.ch <- c
	return l
}

func (l *oneConnListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return &notifyConn{Conn: c, l: l}, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *oneConnListener) Close() error   { l.once.Do(func() { close(l.closed) }); return nil }
func (l *oneConnListener) Addr() net.Addr { return &net.TCPAddr{} }

type notifyConn struct {
	net.Conn
	l *oneConnListener
}

func (c *notifyConn) Close() error { c.l.Close(); return c.Conn.Close() }

func (g *Gateway) mitmServe(w http.ResponseWriter, hostname, hostport string, relays []*up, p *pool) {
	cert, err := g.ca.leaf(hostname)
	if err != nil {
		http.Error(w, "gagal buat sertifikat", http.StatusInternalServerError)
		return
	}
	conn, err := hijack(w)
	if err != nil {
		return
	}
	conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	tconn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	})
	target := "https://" + hostport
	if strings.HasSuffix(hostport, ":443") {
		target = "https://" + hostname
	}
	log.Printf("[%s] mitm %s via %d relay", p.name, hostport, len(relays))
	srv := &http.Server{
		ReadHeaderTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			g.relay(w, r, target, relays, p)
		}),
	}
	srv.Serve(newOneConnListener(tconn))
}

var hopByHop = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	for _, h := range hopByHop {
		dst.Del(h)
	}
}

func (g *Gateway) relay(w http.ResponseWriter, r *http.Request, target string, relays []*up, p *pool) {
	if strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "WebSocket tidak didukung lewat relay Vercel; pakai upstream proxy biasa untuk host ini", http.StatusNotImplemented)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRelayBody+1))
	if err != nil {
		http.Error(w, "gagal baca body", http.StatusBadRequest)
		return
	}
	if len(body) > maxRelayBody {
		http.Error(w, "body terlalu besar untuk relay", http.StatusRequestEntityTooLarge)
		return
	}

	var lastErr error
	for _, u := range relays {
		var rd io.Reader = http.NoBody
		if len(body) > 0 {
			rd = bytes.NewReader(body)
		}
		req, err := http.NewRequestWithContext(r.Context(), r.Method, u.u.String(), rd)
		if err != nil {
			lastErr = err
			continue
		}
		copyHeaders(req.Header, r.Header)
		req.Header.Set("Accept-Encoding", "identity") // Edge fetch sudah decompress, jangan salah header
		req.Header.Set("x-relay-target", target)
		req.Header.Set("x-relay-path", r.URL.RequestURI())
		req.ContentLength = int64(len(body))

		resp, err := g.client.Do(req)
		if err != nil || resp.StatusCode == 502 || resp.StatusCode == 503 || resp.StatusCode == 504 {
			if resp != nil {
				io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
				resp.Body.Close()
				lastErr = fmt.Errorf("status %d", resp.StatusCode)
			} else {
				lastErr = err
			}
			log.Printf("[%s] relay %s gagal: %v", p.name, u.Name, lastErr)
			p.markDown(u)
			continue
		}
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		flushCopy(w, resp.Body)
		resp.Body.Close()
		return
	}
	http.Error(w, fmt.Sprintf("semua relay gagal: %v", lastErr), http.StatusBadGateway)
}

func flushCopy(w http.ResponseWriter, src io.Reader) {
	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// ---------- CA + leaf cert ----------

type leafEntry struct {
	cert    *tls.Certificate
	expires time.Time
}

type CA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	mu    sync.Mutex
	cache map[string]leafEntry
}

func loadOrCreateCA(certPath, keyPath string) (*CA, error) {
	cb, cerr := os.ReadFile(certPath)
	kb, kerr := os.ReadFile(keyPath)
	if cerr == nil && kerr == nil {
		cblk, _ := pem.Decode(cb)
		kblk, _ := pem.Decode(kb)
		if cblk == nil || kblk == nil {
			return nil, errors.New("PEM CA tidak valid")
		}
		cert, err := x509.ParseCertificate(cblk.Bytes)
		if err != nil {
			return nil, err
		}
		key, err := x509.ParseECPrivateKey(kblk.Bytes)
		if err != nil {
			return nil, err
		}
		return &CA{cert: cert, key: key, cache: map[string]leafEntry{}}, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(),
		Subject:               pkix.Name{CommonName: "relay-gateway local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		return nil, err
	}
	log.Printf("CA baru dibuat: %s (trust sertifikat ini di magpie/keychain)", certPath)
	return &CA{cert: cert, key: key, cache: map[string]leafEntry{}}, nil
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 126))
	return n
}

func (ca *CA) leaf(host string) (*tls.Certificate, error) {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	if e, ok := ca.cache[host]; ok && time.Until(e.expires) > 24*time.Hour {
		return e.cert, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	exp := time.Now().AddDate(0, 0, 30)
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     exp,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der, ca.cert.Raw}, PrivateKey: key}
	ca.cache[host] = leafEntry{cert: c, expires: exp}
	return c, nil
}
