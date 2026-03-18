package scan_brute

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
)

// BruteTask 定义爆破任务信息
type BruteTask struct {
	IP       string
	Port     int
	Protocol string
	Service  string
}

// ExecuteBruteForce 执行弱口令验证
func ExecuteBruteForce(ctx context.Context, taskID int) {
	tasks := getBruteTasks(taskID)
	if len(tasks) == 0 {
		return
	}

	queue := make(chan *BruteTask, len(tasks))
	for _, t := range tasks {
		queue <- t
	}
	close(queue)

	var wg sync.WaitGroup
	workers := 10 // 最大并发协议数
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range queue {
				select {
				case <-ctx.Done():
					return
				default:
				}
				bruteService(ctx, taskID, t)
			}
		}()
	}
	wg.Wait()
}

func getBruteTasks(taskID int) []*BruteTask {
	query := `SELECT ip, port, protocol, service_name FROM asset_port WHERE task_id = ? AND state = 'open'`
	rows, err := mysql.DB.Query(query, taskID)
	var tasks []*BruteTask
	if err != nil {
		log.Info("[Brute] 获取端口失败: %v", err)
		return tasks
	}
	defer rows.Close()

	for rows.Next() {
		var ip, protocol sql.NullString
		var port int
		var service sql.NullString
		if err := rows.Scan(&ip, &port, &protocol, &service); err == nil {
			svc := strings.ToLower(service.String)
			if svc == "" {
				svc = strings.ToLower(protocol.String)
			}
			tasks = append(tasks, &BruteTask{
				IP:       ip.String,
				Port:     port,
				Protocol: protocol.String,
				Service:  svc,
			})
		}
	}
	return tasks
}

func bruteService(ctx context.Context, taskID int, t *BruteTask) {
	svc := t.Service

	switch {
	case strings.Contains(svc, "ssh") || t.Port == 22:
		BruteSSH(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "mysql") || t.Port == 3306:
		BruteMySQL(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "redis") || t.Port == 6379:
		BruteRedis(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "postgres") || t.Port == 5432:
		BrutePostgres(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "mssql") || strings.Contains(svc, "ms-sql") || t.Port == 1433:
		BruteMSSQL(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "ftp") || t.Port == 21:
		BruteFTP(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "mongo") || t.Port == 27017:
		BruteMongo(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "rdp") || t.Port == 3389:
		BruteRDP(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "smb") || strings.Contains(svc, "microsoft-ds") || t.Port == 445:
		BruteSMB(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "oracle") || t.Port == 1521:
		BruteOracle(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "telnet") || t.Port == 23:
		BruteTelnet(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "vnc") || t.Port == 5900:
		BruteVNC(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "winrm") || t.Port == 5985 || t.Port == 5986:
		BruteWinRM(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "elasticsearch") || t.Port == 9200:
		BruteElasticSearch(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "jenkins"):
		BruteJenkins(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "tomcat"):
		BruteTomcat(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "weblogic") || t.Port == 7001:
		BruteWeblogic(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "jboss"):
		BruteJBoss(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "activemq") || t.Port == 8161:
		BruteActiveMQ(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "rabbitmq") || t.Port == 15672:
		BruteRabbitMQ(ctx, taskID, t.IP, t.Port)
	case strings.Contains(svc, "ldap") || t.Port == 389:
		BruteLDAP(ctx, taskID, t.IP, t.Port)
	}
}

// reportVuln 统一上报弱口令漏洞
func reportVuln(taskID int, ip string, port int, service string, user string, pass string) {
	// 尝试从资产端口表中获取 Nmap 指纹识别出的详细产品和版本信息
	query := `SELECT service_product, service_version FROM asset_port WHERE task_id = ? AND ip = ? AND port = ? LIMIT 1`
	var product, version sql.NullString
	mysql.DB.QueryRow(query, taskID, ip, port).Scan(&product, &version)

	svcDisplay := strings.ToUpper(service)
	serviceName := service
	if product.Valid && product.String != "" {
		serviceName = product.String
		svcDisplay = product.String
		if version.Valid && version.String != "" {
			svcDisplay += " " + version.String
			serviceName += " " + version.String
		}
	} else {
		serviceName = strings.ToUpper(service)
	}

	vulnName := fmt.Sprintf("%s 弱口令漏洞", svcDisplay)
	desc := fmt.Sprintf("发现 %s 存在弱口令，成功登录的凭据为 Username: '%s', Password: '%s'", serviceName, user, pass)
	if user == "" {
		desc = fmt.Sprintf("发现 %s 存在空口令/未授权访问，Password: '%s'", serviceName, pass)
	}

	log.Info("[Brute] 成功爆破: %s:%d %s", ip, port, desc)

	vuln := map[string]interface{}{
		"task_id":           taskID,
		"target":            ip,
		"ip":                ip,
		"port":              port,
		"service":           service,
		"name":              vulnName,
		"description":       desc,
		"severity":          "high", // 弱口令通常为高危
		"type":              "弱口令",
		"cve":               "",
		"cwe":               "CWE-521",
		"cvss":              "7.5",
		"template_id":       "brute-force",
		"template_path":     "internal",
		"author":            "GoSecProbe",
		"tags":              "bruteforce,weak-password",
		"reference":         "",
		"evidence_request":  "",
		"evidence_response": fmt.Sprintf("Username: %s\nPassword: %s", user, pass),
		"matched_at":        fmt.Sprintf("%s:%d", ip, port),
		"extracted_data":    "",
		"curl_command":      "",
		"metadata":          "{}",
	}

	mysql.SaveVulnerability(vuln)
}
