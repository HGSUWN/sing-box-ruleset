// main.go
package main

import (
    "encoding/json"
    "flag"
    "log"
    "os"
    "path/filepath"
)

// Rule 表示一条通用规则，Type 为映射后的类型（如 "domain", "ip_cidr" 等），
 // Value 为具体的规则值（如 "example.com", "192.168.0.0/16" 等）。
type Rule struct {
    Type  string `json:"type"`
    Value string `json:"value"`
}

// Config 保存各类输出目录及配置项
type Config struct {
    RuleDir                 string
    SingboxOutputDirectory  string
    ClashOutputDirectory    string
}

// NewConfig 根据命令行或默认值生成 Config
func NewConfig() *Config {
    var ruleDir string
    flag.StringVar(&ruleDir, "rule-dir", "./rule", "根规则目录")
    flag.Parse()

    return &Config{
        RuleDir:                ruleDir,
        SingboxOutputDirectory: filepath.Join(ruleDir, "singbox"),
        ClashOutputDirectory:   filepath.Join(ruleDir, "clash"),
    }
}

// 定义哪些类型算作“域名”，哪些算作“IP”
var domainTypes = map[string]bool{
    "domain":         true,
    "domain_suffix":  true,
    "domain_keyword": true,
    "domain_regex":   true,
}

var ipTypes = map[string]bool{
    "ip_cidr":        true,
    "source_ip_cidr": true,
    "geoip":          true,
}

// filterByType 只保留 allowedTypes 中为 true 的那部分规则
func filterByType(rules []Rule, allowedTypes map[string]bool) []Rule {
    out := make([]Rule, 0, len(rules))
    for _, r := range rules {
        if allowedTypes[r.Type] {
            out = append(out, r)
        }
    }
    return out
}

// writeJSON 将 rules 序列化为带缩进的 JSON 并写入 path
func writeJSON(path string, rules []Rule) {
    // 确保目录存在
    if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
        log.Fatalf("无法创建目录 %s: %v", filepath.Dir(path), err)
    }

    data, err := json.MarshalIndent(rules, "", "  ")
    if err != nil {
        log.Fatalf("JSON 序列化失败: %v", err)
    }
    if err := os.WriteFile(path, data, 0o644); err != nil {
        log.Fatalf("写入文件 %s 失败: %v", path, err)
    }
    log.Printf("已写入 %s，共 %d 条规则\n", path, len(rules))
}

// loadAllRules 请根据你的源格式自行实现，这里示例返回硬编码测试用例
func loadAllRules() []Rule {
    return []Rule{
        {Type: "domain", Value: "example.com"},
        {Type: "domain_suffix", Value: "example.org"},
        {Type: "ip_cidr", Value: "192.168.0.0/16"},
        {Type: "geoip", Value: "cn"},
        {Type: "domain_keyword", Value: "test"},
        {Type: "source_ip_cidr", Value: "10.0.0.0/8"},
        {Type: "domain_regex", Value: `^foo\d+\.bar$`},
    }
}

func main() {
    // 初始化配置
    cfg := NewConfig()

    // 加载所有规则
    allRules := loadAllRules()

    // ==== Sing‑box 输出 ====
    // geosite.json（仅域名规则）
    sbGeoSite := filterByType(allRules, domainTypes)
    writeJSON(filepath.Join(cfg.SingboxOutputDirectory, "geosite.json"), sbGeoSite)

    // geoip.json（仅 IP 规则）
    sbGeoIP := filterByType(allRules, ipTypes)
    writeJSON(filepath.Join(cfg.SingboxOutputDirectory, "geoip.json"), sbGeoIP)

    // ==== Clash 输出 ====
    // geosite.json（仅域名规则）
    clashGeoSite := filterByType(allRules, domainTypes)
    writeJSON(filepath.Join(cfg.ClashOutputDirectory, "geosite.json"), clashGeoSite)

    // geoip.json（仅 IP 规则）
    clashGeoIP := filterByType(allRules, ipTypes)
    writeJSON(filepath.Join(cfg.ClashOutputDirectory, "geoip.json"), clashGeoIP)
}
