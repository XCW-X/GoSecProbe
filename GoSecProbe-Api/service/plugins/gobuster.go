package plugins

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// RunGobuster 执行 gobuster 扫描
func RunGobuster(ctx context.Context, taskID int, target string, scanType string) error {
	// 判断插件是否启用
	if !mysql.IsPluginEnabled("gobuster") {
		log.Info("[Gobuster Plugin] NOT enabled, skip scanning.")
		return nil
	}

	pluginDir := "./service/plugins/gobuster"
	extension := ""
	if runtime.GOOS == "windows" {
		extension = ".exe"
	}
	execPath := filepath.Join(pluginDir, "gobuster"+extension)

	if _, err := os.Stat(execPath); err != nil {
		log.Warn("[Gobuster Plugin] executable not found: %s", execPath)
		return nil
	}

	configStr := mysql.GetPluginConfig("gobuster")
	var conf map[string]string
	if configStr != "" {
		_ = json.Unmarshal([]byte(configStr), &conf)
	}

	dirDictName := "fuzz_web.txt"
	dnsDictName := "subdomains_top1000.txt"
	threads := "10"
	timeoutStr := "5s"
	statusCodes := "200,204,301,302,307,401,403"

	if conf != nil {
		if d, ok := conf["dir_dict"]; ok && d != "" {
			dirDictName = d
		}
		if d, ok := conf["dns_dict"]; ok && d != "" {
			dnsDictName = d
		}
		if t, ok := conf["threads"]; ok && t != "" {
			threads = t
		}
		if to, ok := conf["timeout"]; ok && to != "" {
			timeoutStr = to
		}
		if sc, ok := conf["status_codes"]; ok && sc != "" {
			statusCodes = sc
		}
	}

	var wordlist string
	var targetDictName string
	if scanType == "dir" {
		targetDictName = dirDictName
	} else {
		targetDictName = dnsDictName
	}

	d, err := mysql.GetDictByName(targetDictName)
	if err != nil || d.Path == "" {
		log.Warn("[Gobuster Plugin] Failed to find dictionary in DB: %s", targetDictName)
		return fmt.Errorf("dictionary not found in DB: %s", targetDictName)
	}
	wordlist = d.Path

	var cmdArgs []string
	if scanType == "dir" {
		targetUrl := target
		if !strings.HasPrefix(targetUrl, "http://") && !strings.HasPrefix(targetUrl, "https://") {
			targetUrl = "http://" + targetUrl
		}
		cmdArgs = []string{"dir", "-u", targetUrl, "-w", wordlist, "-t", threads, "-s", statusCodes, "--status-codes-blacklist=", "-q", "--no-color", "--timeout", timeoutStr}
	} else if scanType == "dns" {
		domain := strings.TrimPrefix(target, "http://")
		domain = strings.TrimPrefix(domain, "https://")
		domain = strings.Split(domain, ":")[0]
		domain = strings.Split(domain, "/")[0]
		cmdArgs = []string{"dns", "-d", domain, "-w", wordlist, "-t", threads, "-q", "--no-color", "--timeout", timeoutStr}
	} else {
		return fmt.Errorf("unknown gobuster scan type: %s", scanType)
	}

	cmd := exec.CommandContext(ctx, execPath, cmdArgs...)

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	log.Info("[Gobuster Plugin] Running: %s %v", execPath, cmdArgs)

	err = cmd.Run()
	output := out.String()
	// Gobuster can return exit code 1 if it just doesn't find things, but ignore typical errors.
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		log.Warn("[Gobuster Plugin] Timeout for target %s", target)
		return nil
	}

	// Parse outputs
	lines := strings.Split(output, "\n")
	foundItems := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var statusCode = 200
		if strings.Contains(line, "(Status:") {
			parts := strings.Split(line, "(Status:")
			if len(parts) > 1 {
				numParts := strings.Split(strings.TrimSpace(parts[1]), ")")
				if len(numParts) > 0 {
					fmt.Sscanf(numParts[0], "%d", &statusCode)
				}
			}
		}

		if scanType == "dir" && strings.Contains(line, "(Status:") {
			// found dir
			foundItems++

			// Extract the actual path from output line "path (Status: ...)"
			pathPart := strings.TrimSpace(strings.Split(line, "(Status:")[0])
			if !strings.HasPrefix(pathPart, "/") {
				pathPart = "/" + pathPart
			}

			// 这里简单地将发现的目录或子域名保存进vuln表或某种assets表
			saveGobusterResult(taskID, targetUrlFromArgs(cmdArgs), pathPart, "Directory", statusCode)
		} else if scanType == "dns" && strings.HasPrefix(line, "Found:") {
			foundItems++
			saveGobusterResult(taskID, target, strings.TrimSpace(strings.TrimPrefix(line, "Found:")), "Subdomain", statusCode)
		}
	}
	log.Info("[Gobuster Plugin] Finished %s scan for %s. Found %d items.", scanType, target, foundItems)

	return nil
}

func targetUrlFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "-u" && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func saveGobusterResult(taskID int, target string, finding string, findType string, statusCode int) {
	// 将结果插入到Web指纹表中
	url := finding
	if findType == "Directory" {
		if strings.HasSuffix(target, "/") {
			target = strings.TrimSuffix(target, "/")
		}
		if !strings.HasPrefix(finding, "/") {
			finding = "/" + finding
		}
		url = target + finding
	} else if findType == "Subdomain" {
		url = "http://" + finding
	}

	// 扫描标注：目录扫描 / 子域名爆破，附加 GobusterPlugin 来源
	serverType := "目录扫描/GobusterPlugin"
	if findType == "Subdomain" {
		serverType = "子域名爆破/GobusterPlugin"
	}

	// 获取或创建asset_id，避免外键约束失败
	assetValue := target
	if after := strings.TrimPrefix(assetValue, "http://"); after != assetValue {
		assetValue = strings.Split(after, "/")[0]
	} else if after := strings.TrimPrefix(assetValue, "https://"); after != assetValue {
		assetValue = strings.Split(after, "/")[0]
	}
	assetID, err := mysql.GetOrCreateAsset(assetValue, "ip")
	if err != nil {
		log.Warn("[Gobuster Plugin] Failed to get/create asset for %s: %v", assetValue, err)
		return
	}

	// 保存 Gobuster 发现的原始记录
	_ = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		nil, // portID
		url,
		"",                         // ip
		0,                          // port
		"",                         // protocol
		"",                         // title
		statusCode,                 // statusCode
		serverType,                 // server 设为标注
		"",                         // content_type
		0,                          // content_length
		0,                          // response_time
		[]string{"GobusterPlugin"}, // technologies
		[]string{},                 // frameworks
		[]string{},                 // matched_rules
		"",                         // favicon_hash
		map[string]string{},        // headers
	)

	// 如果是 3xx 重定向，跟随一次以获取真实页面的指纹
	if statusCode >= 300 && statusCode < 400 {
		go followRedirectAndSave(taskID, assetID, url, serverType)
	}
}

// followRedirectAndSave 跟随重定向获取真实页面信息并保存
func followRedirectAndSave(taskID int, assetID int64, originalURL string, serverType string) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}

	resp, err := client.Get(originalURL)
	if err != nil {
		log.Warn("[Gobuster Plugin] Failed to follow redirect for %s: %v", originalURL, err)
		return
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	if finalURL == originalURL {
		return // No real redirect happened
	}

	// 读取响应 body 最多 64KB 来提取标题
	buf := make([]byte, 65536)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	title := extractTitle(body)
	server := resp.Header.Get("Server")
	contentType := resp.Header.Get("Content-Type")

	// 将标题等信息收窄成响应的map
	headers := map[string]string{}
	for k, vals := range resp.Header {
		if len(vals) > 0 {
			headers[k] = vals[0]
		}
	}

	_ = mysql.SaveWebFingerprint(
		taskID,
		assetID,
		nil,
		finalURL,
		"", // ip
		0,  // port
		"", // protocol
		title,
		resp.StatusCode,
		server,
		contentType,
		0,
		0,
		[]string{"GobusterPlugin"},
		[]string{},
		[]string{},
		"",
		headers,
	)
	log.Info("[Gobuster Plugin] Followed redirect %s -> %s (title: %s)", originalURL, finalURL, title)
}

// extractTitle 从 HTML 中提取 <title> 标签内容
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	return strings.TrimSpace(body[start : start+end])
}
