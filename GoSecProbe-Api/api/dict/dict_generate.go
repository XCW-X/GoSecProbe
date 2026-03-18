package dict

import (
	"GoSecProbe/common/log"
	"GoSecProbe/common/mysql"
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
)

// SocialGenRequest 社会工程字典生成请求
type SocialGenRequest struct {
	Name      string   `json:"name"`       // 姓名/拼音
	Nickname  string   `json:"nickname"`   // 昵称
	Birthday  string   `json:"birthday"`   // 生日 YYYYMMDD
	Phone     string   `json:"phone"`      // 手机号
	Email     string   `json:"email"`      // 邮箱
	Company   string   `json:"company"`    // 公司
	Address   string   `json:"address"`    // 地址/城市
	SystemTag string   `json:"system_tag"` // 系统名关键字
	PetName   string   `json:"pet_name"`   // 宠物名
	Extra     string   `json:"extra"`      // 其他自定义词
	Rules     []string `json:"rules"`      // 规则集合
	DictName  string   `json:"dict_name"`  // 自定义字典名称
}

// ComboGenRequest Combo字典生成请求
type ComboGenRequest struct {
	Bases    []string `json:"bases"`     // 基础词列表（每列）
	Joins    []string `json:"joins"`     // 连接符列表（如 _, @, -, "" 等）
	Orders   [][]int  `json:"orders"`    // 列顺序组合，如 [[0,1],[1,0],[0,1,2]] 表示 AB, BA, ABC
	Rules    []string `json:"rules"`     // 追加规则
	DictName string   `json:"dict_name"` // 自定义字典名称
}

// GenerateSocialDict 生成社会工程字典
func GenerateSocialDict(c *gin.Context) {
	var req SocialGenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "参数错误: " + err.Error()})
		return
	}

	// 收集所有基础词
	bases := collectBases(req)
	if len(bases) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "请至少填写一个信息字段"})
		return
	}

	// 生成变体
	words := generateSocialVariants(bases, req.Birthday, req.Rules)

	// 去重
	words = deduplicate(words)

	// 写入文件
	dictName := req.DictName
	if dictName == "" {
		dictName = fmt.Sprintf("social_%s_%d.txt", sanitize(req.Name), time.Now().Unix())
	}
	if !strings.HasSuffix(dictName, ".txt") {
		dictName += ".txt"
	}

	path, linesCnt, err := saveDictFile(dictName, words)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": "写入字典文件失败: " + err.Error()})
		return
	}

	// 入库
	info, _ := os.Stat(path)
	d := mysql.Dict{
		Name:     dictName,
		Type:     "generated",
		Category: "密码字典",
		Size:     info.Size(),
		LinesCnt: linesCnt,
		Path:     path,
	}
	if err := mysql.UpsertDict(d); err != nil {
		log.Warn("Failed to register generated dict: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "生成成功",
		"data": gin.H{
			"name":      dictName,
			"lines_cnt": linesCnt,
			"size":      info.Size(),
		},
	})
}

// GenerateComboDict 生成Combo字典
func GenerateComboDict(c *gin.Context) {
	var req ComboGenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "参数错误: " + err.Error()})
		return
	}

	// 解析每列的基础词
	columns := make([][]string, 0)
	for _, base := range req.Bases {
		lines := splitLines(base)
		if len(lines) > 0 {
			columns = append(columns, lines)
		}
	}

	if len(columns) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"code": 40000, "msg": "请至少填写一列基础词"})
		return
	}

	joins := req.Joins
	if len(joins) == 0 {
		joins = []string{""}
	}

	// 如果没有指定 orders，默认按原始顺序全列一种组合
	orders := req.Orders
	if len(orders) == 0 {
		def := make([]int, len(columns))
		for i := range def {
			def[i] = i
		}
		orders = [][]int{def}
	}

	// 对每种顺序分别做笛卡尔积，合并所有结果
	var allWords []string
	for _, order := range orders {
		// 验证 order 合法性：索引必须在 [0, len(columns)) 内
		arranged := make([][]string, 0, len(order))
		valid := true
		for _, idx := range order {
			if idx < 0 || idx >= len(columns) {
				valid = false
				break
			}
			arranged = append(arranged, columns[idx])
		}
		if !valid || len(arranged) == 0 {
			continue
		}
		words := cartesianProduct(arranged, joins)
		allWords = append(allWords, words...)
	}

	// 应用附加规则
	allWords = applyComboRules(allWords, req.Rules)

	// 去重
	allWords = deduplicate(allWords)

	// 写入文件
	dictName := req.DictName
	if dictName == "" {
		dictName = fmt.Sprintf("combo_%d.txt", time.Now().Unix())
	}
	if !strings.HasSuffix(dictName, ".txt") {
		dictName += ".txt"
	}

	path, linesCnt, err := saveDictFile(dictName, allWords)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"code": 50000, "msg": "写入字典文件失败: " + err.Error()})
		return
	}

	// 入库
	info, _ := os.Stat(path)
	d := mysql.Dict{
		Name:     dictName,
		Type:     "generated",
		Category: "密码字典",
		Size:     info.Size(),
		LinesCnt: linesCnt,
		Path:     path,
	}
	if err := mysql.UpsertDict(d); err != nil {
		log.Warn("Failed to register generated dict: %v", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 20000,
		"msg":  "生成成功",
		"data": gin.H{
			"name":      dictName,
			"lines_cnt": linesCnt,
			"size":      info.Size(),
		},
	})
}

// ----- helpers -----

func collectBases(req SocialGenRequest) []string {
	set := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" {
			set[s] = true
		}
	}

	fields := []string{req.Name, req.Nickname, req.Phone, req.Company, req.Address, req.SystemTag, req.PetName, req.Extra}
	for _, f := range fields {
		for _, part := range strings.FieldsFunc(f, func(r rune) bool {
			return r == '，' || r == ',' || r == ' '
		}) {
			add(part)
		}
	}
	// email user part
	if req.Email != "" {
		parts := strings.SplitN(req.Email, "@", 2)
		add(parts[0])
	}

	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	return result
}

func generateSocialVariants(bases []string, birthday string, rules []string) []string {
	ruleSet := map[string]bool{}
	for _, r := range rules {
		ruleSet[r] = true
	}

	set := map[string]bool{}
	add := func(s string) {
		s = strings.TrimSpace(s)
		if len(s) >= 4 {
			set[s] = true
		}
	}

	// 日期变体
	dateVariants := []string{}
	if birthday != "" {
		b := strings.ReplaceAll(birthday, "-", "")
		b = strings.ReplaceAll(b, "/", "")
		if len(b) >= 8 {
			year := b[0:4]
			month := b[4:6]
			day := b[6:8]
			dateVariants = append(dateVariants,
				b,              // 19901231
				b[2:],          // 901231
				year,           // 1990
				month+day,      // 1231
				year+month,     // 199012
				day+month+year, // 31121990
				month+day+year, // 12311990
			)
		}
	}

	suffixes := []string{"", "123", "321", "1", "2", "12", "abc", "!"}
	prefixes := []string{"", "i", "I"}

	for _, base := range bases {
		lower := strings.ToLower(base)
		upper := strings.ToUpper(base)
		title := strings.Title(strings.ToLower(base))
		// Base caps variants
		for _, b := range []string{base, lower, upper, title} {
			add(b)
			if ruleSet["special"] {
				for _, suf := range []string{"!", "@", "#"} {
					add(b + suf)
				}
			}
			// with numbers suffix
			for _, suf := range suffixes {
				add(b + suf)
			}
			for _, pre := range prefixes {
				add(pre + b)
			}
		}

		// combine with dates
		if ruleSet["date"] {
			for _, dv := range dateVariants {
				add(lower + dv)
				add(upper + dv)
				add(title + dv)
				add(dv + lower)
			}
		}

		// leet speak
		if ruleSet["leet"] {
			add(leet(lower))
		}

		// reverse
		if ruleSet["reverse"] {
			add(reverseStr(lower))
		}

		// doubles e.g. "abc" -> "abcabc"
		if ruleSet["double"] {
			add(lower + lower)
		}
	}

	// combinations between pairs
	for i := 0; i < len(bases); i++ {
		for j := i + 1; j < len(bases); j++ {
			a := strings.ToLower(bases[i])
			b := strings.ToLower(bases[j])
			add(a + b)
			add(b + a)
			add(a + "_" + b)
			add(a + "." + b)
			for _, dv := range dateVariants {
				add(a + b + dv)
			}
		}
	}

	// date only as passwords
	for _, dv := range dateVariants {
		add(dv)
	}

	result := make([]string, 0, len(set))
	for k := range set {
		result = append(result, k)
	}
	return result
}

func cartesianProduct(columns [][]string, joins []string) []string {
	if len(columns) == 0 {
		return nil
	}

	result := columns[0]
	for i := 1; i < len(columns); i++ {
		next := make([]string, 0, len(result)*len(columns[i])*len(joins))
		for _, a := range result {
			for _, b := range columns[i] {
				for _, j := range joins {
					next = append(next, a+j+b)
				}
			}
		}
		result = next
	}
	return result
}

func applyComboRules(words []string, rules []string) []string {
	ruleSet := map[string]bool{}
	for _, r := range rules {
		ruleSet[r] = true
	}

	if len(ruleSet) == 0 {
		return words
	}

	extra := []string{}
	for _, w := range words {
		if ruleSet["upper"] {
			extra = append(extra, strings.ToUpper(w))
		}
		if ruleSet["title"] {
			extra = append(extra, strings.Title(strings.ToLower(w)))
		}
		if ruleSet["numbers"] {
			for _, n := range []string{"123", "1234", "12345", "123456", "1", "2", "!"} {
				extra = append(extra, w+n)
			}
		}
		if ruleSet["leet"] {
			extra = append(extra, leet(w))
		}
		if ruleSet["reverse"] {
			extra = append(extra, reverseStr(w))
		}
	}

	return append(words, extra...)
}

func deduplicate(words []string) []string {
	seen := make(map[string]bool, len(words))
	res := make([]string, 0, len(words))
	for _, w := range words {
		if !seen[w] && w != "" {
			seen[w] = true
			res = append(res, w)
		}
	}
	return res
}

func saveDictFile(name string, words []string) (string, int64, error) {
	dir := "./uploads/dict"
	os.MkdirAll(dir, 0755)
	path := filepath.Join(dir, name)

	f, err := os.Create(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	var cnt int64
	for _, word := range words {
		_, err := w.WriteString(word + "\n")
		if err != nil {
			return "", 0, err
		}
		cnt++
	}
	return path, cnt, w.Flush()
}

func splitLines(s string) []string {
	var result []string
	scanner := bufio.NewScanner(strings.NewReader(s))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			result = append(result, line)
		}
	}
	return result
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "dict"
	}
	return b.String()
}

func leet(s string) string {
	r := strings.NewReplacer(
		"a", "4", "e", "3", "i", "1",
		"o", "0", "s", "5", "t", "7",
	)
	return r.Replace(s)
}

func reverseStr(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
