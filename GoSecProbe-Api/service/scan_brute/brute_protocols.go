package scan_brute

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
	_ "github.com/microsoft/go-mssqldb"
	"github.com/projectdiscovery/go-smb2"
	_ "github.com/sijms/go-ora/v2"
	"github.com/tomatome/grdp/core"
	"github.com/tomatome/grdp/glog"
	"github.com/tomatome/grdp/protocol/nla"
	"github.com/tomatome/grdp/protocol/pdu"
	"github.com/tomatome/grdp/protocol/sec"
	"github.com/tomatome/grdp/protocol/t125"
	"github.com/tomatome/grdp/protocol/tpkt"
	"github.com/tomatome/grdp/protocol/x224"
	"golang.org/x/crypto/ssh"
)

// SSH
func BruteSSH(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("ssh")
	address := fmt.Sprintf("%s:%d", ip, port)
	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			config := &ssh.ClientConfig{
				User: user,
				Auth: []ssh.AuthMethod{
					ssh.Password(pass),
				},
				Timeout:         3 * time.Second,
				HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			}

			client, err := ssh.Dial("tcp", address, config)
			if err == nil {
				client.Close()
				reportVuln(taskID, ip, port, "SSH", user, pass)
				return // 找到了就不继续试了
			}
		}
	}
}

// MySQL
func BruteMySQL(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("mysql")
	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/?timeout=3s", user, pass, ip, port)
			db, err := sql.Open("mysql", dsn)
			if err != nil {
				continue
			}

			db.SetConnMaxLifetime(2 * time.Second)
			if err := db.Ping(); err == nil {
				db.Close()
				reportVuln(taskID, ip, port, "MySQL", user, pass)
				return
			}
			db.Close()
		}
	}
}

// PostgreSQL
func BrutePostgres(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("postgres")
	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable&connect_timeout=3", user, pass, ip, port)
			db, err := sql.Open("postgres", dsn)
			if err != nil {
				continue
			}
			db.SetConnMaxLifetime(2 * time.Second)
			if err := db.Ping(); err == nil {
				db.Close()
				reportVuln(taskID, ip, port, "PostgreSQL", user, pass)
				return
			}
			db.Close()
		}
	}
}

// MSSQL
func BruteMSSQL(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("mssql")
	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			dsn := fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;encrypt=disable;connection timeout=3", ip, port, user, pass)
			db, err := sql.Open("sqlserver", dsn)
			if err != nil {
				continue
			}
			db.SetConnMaxLifetime(2 * time.Second)
			if err := db.Ping(); err == nil {
				db.Close()
				reportVuln(taskID, ip, port, "MSSQL", user, pass)
				return
			}
			db.Close()
		}
	}
}

// Redis (直接发raw command因为可能没有user验证)
func BruteRedis(ctx context.Context, taskID int, ip string, port int) {
	_, passes := getDicts("redis")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, pass := range passes {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := net.DialTimeout("tcp", address, 3*time.Second)
		if err != nil {
			return // 连不上直接退
		}

		conn.SetDeadline(time.Now().Add(3 * time.Second))
		if pass == "" {
			conn.Write([]byte("PING\r\n"))
		} else {
			conn.Write([]byte(fmt.Sprintf("AUTH %s\r\n", pass)))
		}

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		conn.Close()

		if err == nil {
			resp := string(buf[:n])
			if strings.Contains(resp, "+PONG") || strings.Contains(resp, "+OK") {
				reportVuln(taskID, ip, port, "Redis", "", pass)
				return
			}
			if strings.Contains(resp, "-NOAUTH") {
				continue // 密码错或需要密
			}
			if strings.Contains(resp, "-ERR invalid password") {
				continue
			}
		}
	}
}

// FTP (简单发 USER 和 PASS)
func BruteFTP(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("ftp")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			func() {
				conn, err := net.DialTimeout("tcp", address, 3*time.Second)
				if err != nil {
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(4 * time.Second))

				// read banner
				buf := make([]byte, 1024)
				conn.Read(buf)

				conn.Write([]byte(fmt.Sprintf("USER %s\r\n", user)))
				conn.Read(buf) // expect 331 Password required

				conn.Write([]byte(fmt.Sprintf("PASS %s\r\n", pass)))
				n, _ := conn.Read(buf)
				resp := string(buf[:n])

				if strings.HasPrefix(resp, "230 ") { // 230 User logged in, proceed
					reportVuln(taskID, ip, port, "FTP", user, pass)
					return
				}
			}()
		}
	}
}

// Mongo
func BruteMongo(ctx context.Context, taskID int, ip string, port int) {
	// MongoDB的协议爆破也可以用简单包或者跳过，我们先暂存未授权尝试，需要密码的话可以用 bson/socket。
	// 但实际也可以使用标准的 mongo driver.
	// 不过既然这可能有些复杂，暂时实现简单的未授权访问检测。
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return
	}
	defer conn.Close()
	// 这只是占位，可以通过官方 driver 实现或者仅报告未授权
}

// httpBasicBrute 是 HTTP 基础认证的通用爆破
func httpBasicBrute(ctx context.Context, taskID int, ip string, port int, service, path string, users, passes []string, expectedCode int, expectedContent string) {
	address := fmt.Sprintf("http://%s:%d%s", ip, port, path)
	client := &http.Client{Timeout: 3 * time.Second}

	// 先验证目标是否可达
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	resp.Body.Close()

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			req, _ := http.NewRequestWithContext(ctx, "GET", address, nil)
			req.SetBasicAuth(user, pass)

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == expectedCode {
				if expectedContent != "" {
					body, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if strings.Contains(string(body), expectedContent) {
						reportVuln(taskID, ip, port, service, user, pass)
						return
					}
				} else {
					resp.Body.Close()
					reportVuln(taskID, ip, port, service, user, pass)
					return
				}
			} else {
				resp.Body.Close()
			}
		}
	}
}

func BruteElasticSearch(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("elasticsearch")
	httpBasicBrute(ctx, taskID, ip, port, "ElasticSearch", "/", users, passes, 200, "cluster_name")
}

func BruteJenkins(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("jenkins")
	httpBasicBrute(ctx, taskID, ip, port, "Jenkins", "/", users, passes, 200, "Dashboard")
}

func BruteTomcat(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("tomcat")
	httpBasicBrute(ctx, taskID, ip, port, "Tomcat", "/manager/html", users, passes, 200, "")
}

func BruteJBoss(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("jboss")
	httpBasicBrute(ctx, taskID, ip, port, "JBoss", "/jmx-console/", users, passes, 200, "")
}

func BruteActiveMQ(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("activemq")
	httpBasicBrute(ctx, taskID, ip, port, "ActiveMQ", "/admin/", users, passes, 200, "")
}

func BruteRabbitMQ(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("rabbitmq")
	httpBasicBrute(ctx, taskID, ip, port, "RabbitMQ", "/api/whoami", users, passes, 200, "")
}

func BruteWinRM(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("winrm")
	httpBasicBrute(ctx, taskID, ip, port, "WinRM", "/wsman", users, passes, 400, "Bad Request") // Auth success on WinRM often returns 400 or 500 when not sending proper XML
}

func BruteWeblogic(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("weblogic")
	address := fmt.Sprintf("http://%s:%d/console/j_security_check", ip, port)
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't redirect
		},
	}

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			body := fmt.Sprintf("j_username=%s&j_password=%s", user, pass)
			req, err := http.NewRequestWithContext(ctx, "POST", address, strings.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			if resp.StatusCode == 302 && strings.Contains(resp.Header.Get("Location"), "console.portal") {
				resp.Body.Close()
				reportVuln(taskID, ip, port, "Weblogic", user, pass)
				return
			}
			resp.Body.Close()
		}
	}
}

func BruteLDAP(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("ldap")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}
			l, err := ldap.DialURL(fmt.Sprintf("ldap://%s", address))
			if err != nil {
				return
			}
			err = l.Bind(user, pass)
			if err == nil {
				l.Close()
				reportVuln(taskID, ip, port, "LDAP", user, pass)
				return
			}
			l.Close()
		}
	}
}

func BruteOracle(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("oracle")
	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}
			dsn := fmt.Sprintf("oracle://%s:%s@%s:%d/orcl", user, pass, ip, port)
			db, err := sql.Open("oracle", dsn)
			if err != nil {
				continue
			}
			db.SetConnMaxLifetime(2 * time.Second)
			if err := db.PingContext(ctx); err == nil {
				db.Close()
				reportVuln(taskID, ip, port, "Oracle", user, pass)
				return
			}
			db.Close()
		}
	}
}

func BruteSMB(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("smb")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return
			}

			d := &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					User:     user,
					Password: pass,
				},
			}

			s, err := d.Dial(conn)
			if err == nil {
				s.Logoff()
				conn.Close()
				reportVuln(taskID, ip, port, "SMB", user, pass)
				return
			}
			conn.Close()
		}
	}
}

func BruteTelnet(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("telnet")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Simple timeout telnet brute without complex lib
			conn, err := net.DialTimeout("tcp", address, 3*time.Second)
			if err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(5 * time.Second))
			defer conn.Close()

			buf := make([]byte, 1024)
			conn.Read(buf) // welcome banner
			conn.Write([]byte(user + "\r\n"))
			conn.Read(buf) // wait for password prompt
			conn.Write([]byte(pass + "\r\n"))

			n, _ := conn.Read(buf)
			resp := string(buf[:n])
			if strings.Contains(resp, ">") || strings.Contains(resp, "$") || strings.Contains(resp, "#") || strings.Contains(strings.ToLower(resp), "login successful") {
				reportVuln(taskID, ip, port, "Telnet", user, pass)
				return
			}
		}
	}
}

func BruteVNC(ctx context.Context, taskID int, ip string, port int) {
	address := fmt.Sprintf("%s:%d", ip, port)

	// Since we lack go-vnc reliably, we perform basic detection or use dummy for now to avoid freezing
	// Real VNC requires DES encryption of the challenge.
	select {
	case <-ctx.Done():
		return
	default:
	}

	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return
	}
	conn.SetDeadline(time.Now().Add(3 * time.Second))
	defer conn.Close()

	// 读 Server ProtocolVersion
	buf := make([]byte, 12)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	// 返回相同的 ProtocolVersion
	conn.Write(buf)

	// VNC Auth handshakes are too complex for a pure manual socket without crypto/des blocks,
	// If password is empty (No Auth), we can detect it.
	// Server sends num security types (1 byte), security types (N bytes).
	secTypesBuf := make([]byte, 1)
	_, err = io.ReadFull(conn, secTypesBuf)
	if err == nil && secTypesBuf[0] > 0 {
		types := make([]byte, secTypesBuf[0])
		io.ReadFull(conn, types)
		for _, t := range types {
			if t == 1 { // 1 = None (No authentication)
				reportVuln(taskID, ip, port, "VNC", "", "No Auth")
				return
			}
		}
	}
}

func BruteRDP(ctx context.Context, taskID int, ip string, port int) {
	users, passes := getDicts("rdp")
	address := fmt.Sprintf("%s:%d", ip, port)

	for _, user := range users {
		for _, pass := range passes {
			select {
			case <-ctx.Done():
				return
			default:
			}

			if ok, _ := rdpConn(address, "", user, pass, 5); ok {
				reportVuln(taskID, ip, port, "RDP", user, pass)
				return
			}
		}
	}
}

func rdpConn(host, domain, user, pass string, timeoutSeconds int) (bool, error) {
	defer func() {
		if r := recover(); r != nil {
			// ignore panic
		}
	}()

	client := newRdpClient(host)
	if err := client.Login(domain, user, pass, int64(timeoutSeconds)); err != nil {
		return false, err
	}
	return true, nil
}

type rdpClient struct {
	Host string
	tpkt *tpkt.TPKT
	x224 *x224.X224
	mcs  *t125.MCSClient
	sec  *sec.Client
	pdu  *pdu.Client
}

func newRdpClient(host string) *rdpClient {
	glog.SetLevel(glog.NONE)
	logger := log.New(os.Stdout, "", 0)
	glog.SetLogger(logger)
	return &rdpClient{Host: host}
}

func (g *rdpClient) Login(domain, user, pwd string, timeout int64) error {
	conn, err := net.DialTimeout("tcp", g.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	g.initProtocolStack(conn, domain, user, pwd)

	if err = g.x224.Connect(); err != nil {
		return err
	}

	var wg sync.WaitGroup
	breakFlag := false
	wg.Add(1)

	var loginErr error
	g.setupEventHandlers(&wg, &breakFlag, &loginErr)

	connectionDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(connectionDone)
	}()

	select {
	case <-connectionDone:
		return loginErr
	case <-time.After(time.Duration(timeout) * time.Second):
		if !breakFlag {
			breakFlag = true
			wg.Done()
		}
		return errors.New("timeout")
	}
}

func (g *rdpClient) initProtocolStack(conn net.Conn, domain, user, pwd string) {
	g.tpkt = tpkt.New(core.NewSocketLayer(conn), nla.NewNTLMv2(domain, user, pwd))
	g.x224 = x224.New(g.tpkt)
	g.mcs = t125.NewMCSClient(g.x224)
	g.sec = sec.NewClient(g.mcs)
	g.pdu = pdu.NewClient(g.sec)

	g.sec.SetUser(user)
	g.sec.SetPwd(pwd)
	g.sec.SetDomain(domain)

	g.tpkt.SetFastPathListener(g.sec)
	g.sec.SetFastPathListener(g.pdu)
	g.pdu.SetFastPathSender(g.tpkt)
}

func (g *rdpClient) setupEventHandlers(wg *sync.WaitGroup, breakFlag *bool, err *error) {
	g.pdu.On("error", func(e error) {
		*err = e
		g.pdu.Emit("done")
	})

	g.pdu.On("close", func() {
		*err = errors.New("closed")
		g.pdu.Emit("done")
	})

	g.pdu.On("success", func() {
		*err = nil
		g.pdu.Emit("done")
	})

	g.pdu.On("ready", func() {
		g.pdu.Emit("done")
	})

	g.pdu.On("done", func() {
		if !*breakFlag {
			*breakFlag = true
			wg.Done()
		}
	})
}
