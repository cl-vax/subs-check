package proxies

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	u "net/url"
	"strings"
	"sync"
	"time"

	"github.com/beck-8/subs-check/config"
	"github.com/beck-8/subs-check/utils"
	"github.com/metacubex/mihomo/common/convert"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
)

// isValidProxy checks if a proxy node meets the specified filtering criteria.
// 筛选出如果协议是shadowsocks、vless或vmess，则需要开启ws或tls，或http伪装；排除reality
func isValidProxy(proxy map[string]any) bool {
	// 获取协议类型
	protocol, ok := proxy["type"].(string)
	if !ok {
		return false // 没有类型字段，直接丢弃
	}

	// 规则 1: 协议必须是 shadowsocks, vless, 或 vmess
	allowedProtocols := []string{"ss", "shadowsocks", "vless", "vmess"}
	if !lo.Contains(allowedProtocols, protocol) {
		return true // 如果不是我们关心的协议，直接放行，不应用后续规则
	}
    
    // --- 如果代码运行到这里，说明协议是 ss, vless, 或 vmess ---

	// 规则 3: 排除所有 REALITY 节点
	if network, ok := proxy["network"].(string); ok && network == "tcp" {
		if _, realityExists := proxy["reality-opts"]; realityExists {
			slog.Debug("筛选节点：协议为tcp，检测到reality-opts，已排除", "name", proxy["name"])
			return false
		}
	}
    // 另一种更通用的判断方式，兼容不同客户端写法
    if tlsSettings, ok := proxy["tls"].(bool); ok && tlsSettings {
         if _, realityExists := proxy["reality-opts"]; realityExists {
             slog.Debug("筛选节点：协议tls为true，检测到reality-opts，已排除", "name", proxy["name"])
			 return false
         }
    }


	// 规则 2: 必须开启 ws, tls, 或 http 伪装
	// 检查是否开启 tls
	if tlsEnabled, ok := proxy["tls"].(bool); ok && tlsEnabled {
		return true // 满足条件：开启了tls
	}

	// 检查传输方式是否是 ws
	if network, ok := proxy["network"].(string); ok && network == "ws" {
		return true // 满足条件：传输方式是ws
	}
    
	// 检查伪装类型是否是 http (通常用于 vmess)
	if header, ok := proxy["header"].(map[string]any); ok {
		if headerType, ok := header["type"].(string); ok && headerType == "http" {
			return true // 满足条件：http伪装
		}
	}
    // 兼容另一种写法 (clash classic)
    if network, ok := proxy["network"].(string); ok && network == "http" {
        return true // 满足条件：http伪装
    }


	// 如果以上所有伪装条件都不满足，则丢弃该节点
	slog.Debug("筛选节点：协议匹配但缺少必要的伪装(ws/tls/http)，已排除", "name", proxy["name"], "type", protocol)
	return false
}

func GetProxies() ([]map[string]any, error) {

	// 解析本地与远程订阅清单
	subUrls := resolveSubUrls()
	slog.Info("订阅链接数量", "本地", len(config.GlobalConfig.SubUrls), "远程", len(config.GlobalConfig.SubUrlsRemote), "总计", len(subUrls))

	if len(config.GlobalConfig.NodeType) > 0 {
		slog.Info("只筛选用户设置的协议", "type", config.GlobalConfig.NodeType)
	}

	var wg sync.WaitGroup
	proxyChan := make(chan map[string]any, 1)                              // 缓冲通道存储解析的代理
	concurrentLimit := make(chan struct{}, config.GlobalConfig.Concurrent) // 限制并发数

	// 启动收集结果的协程
	var mihomoProxies []map[string]any
	done := make(chan struct{})
	go func() {
		for proxy := range proxyChan {
			mihomoProxies = append(mihomoProxies, proxy)
		}
		done <- struct{}{}
	}()

	// 启动工作协程
	for _, subUrl := range subUrls {
		wg.Add(1)
		concurrentLimit <- struct{}{} // 获取令牌

		go func(url string) {
			defer wg.Done()
			defer func() { <-concurrentLimit }() // 释放令牌

			data, err := GetDateFromSubs(url)
			if err != nil {
				slog.Error(fmt.Sprintf("获取订阅链接错误跳过: %v", err))
				return
			}

			var tag string
			if d, err := u.Parse(url); err == nil {
				tag = d.Fragment
			}

			var con map[string]any
			err = yaml.Unmarshal(data, &con)
			if err != nil {
				proxyList, err := convert.ConvertsV2Ray(data)
				if err != nil {
					slog.Error(fmt.Sprintf("解析proxy错误: %v", err), "url", url)
					return
				}
				slog.Debug(fmt.Sprintf("获取订阅链接: %s，有效节点数量: %d", url, len(proxyList)))
				for _, proxy := range proxyList {
					// 只测试指定协议
					if t, ok := proxy["type"].(string); ok {
						if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
							continue
						}
					}

                    // ==================== 新增筛选逻辑 ====================
                    if !isValidProxy(proxy) {
                        continue // 如果不符合我们的复杂规则，则跳过此节点
                    }
                    // ======================================================

					// 为每个节点添加订阅链接来源信息和备注
					proxy["sub_url"] = url
					proxy["sub_tag"] = tag
					proxyChan <- proxy
				}
				return
			}

			proxyInterface, ok := con["proxies"]
			if !ok || proxyInterface == nil {
				slog.Error(fmt.Sprintf("订阅链接没有proxies: %s", url))
				return
			}

			proxyList, ok := proxyInterface.([]any)
			if !ok {
				return
			}
			slog.Debug(fmt.Sprintf("获取订阅链接: %s，有效节点数量: %d", url, len(proxyList)))
			for _, proxy := range proxyList {
				if proxyMap, ok := proxy.(map[string]any); ok {
					if t, ok := proxyMap["type"].(string); ok {
						// 只测试指定协议
						if len(config.GlobalConfig.NodeType) > 0 && !lo.Contains(config.GlobalConfig.NodeType, t) {
							continue
						}
						// 虽然支持mihomo支持下划线，但是这里为了规范，还是改成横杠
						// todo: 不知道后边还有没有这类问题
						switch t {
						case "hysteria2", "hy2":
							if _, ok := proxyMap["obfs_password"]; ok {
								proxyMap["obfs-password"] = proxyMap["obfs_password"]
								delete(proxyMap, "obfs_password")
							}
						}
					}
                    if !isValidProxy(proxyMap) {
						continue // 如果不符合我们的复杂规则，则跳过此节点
					}
					// 为每个节点添加订阅链接来源信息和备注
					proxyMap["sub_url"] = url
					proxyMap["sub_tag"] = tag
					proxyChan <- proxyMap
				}
			}
		}(utils.WarpUrl(subUrl))
	}

	// 等待所有工作协程完成
	wg.Wait()
	close(proxyChan)
	<-done // 等待收集完成

	return mihomoProxies, nil
}

// from 3k
// resolveSubUrls 合并本地与远程订阅清单并去重
func resolveSubUrls() []string {
	urls := make([]string, 0, len(config.GlobalConfig.SubUrls))
	// 本地配置
	urls = append(urls, config.GlobalConfig.SubUrls...)

	// 远程清单
	if len(config.GlobalConfig.SubUrlsRemote) != 0 {
		for _, d := range config.GlobalConfig.SubUrlsRemote {
			if remote, err := fetchRemoteSubUrls(utils.WarpUrl(d)); err != nil {
				slog.Warn("获取远程订阅清单失败，已忽略", "err", err)
			} else {
				urls = append(urls, remote...)
			}
		}

	}

	// 规范化与去重
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, s := range urls {
		s = strings.TrimSpace(s)
		if s == "" || strings.HasPrefix(s, "#") { // 跳过空行与注释
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// fetchRemoteSubUrls 从远程地址读取订阅URL清单
// 支持两种格式：
// 1) 纯文本，按换行分隔，支持以 # 开头的注释与空行
// 2) YAML/JSON 的字符串数组
func fetchRemoteSubUrls(listURL string) ([]string, error) {
	if listURL == "" {
		return nil, errors.New("empty list url")
	}
	data, err := GetDateFromSubs(listURL)
	if err != nil {
		return nil, err
	}

	// 优先尝试解析为字符串数组（YAML/JSON兼容）
	var arr []string
	if err := yaml.Unmarshal(data, &arr); err == nil && len(arr) > 0 {
		return arr, nil
	}

	// 回退为按行解析
	res := make([]string, 0, 16)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		res = append(res, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return res, nil
}

// 订阅链接中获取数据
func GetDateFromSubs(subUrl string) ([]byte, error) {
	maxRetries := config.GlobalConfig.SubUrlsReTry
	// 重试间隔
	retryInterval := config.GlobalConfig.SubUrlsRetryInterval
	if retryInterval == 0 {
		retryInterval = 1
	}
	// 超时时间
	timeout := config.GlobalConfig.SubUrlsTimeout
	if timeout == 0 {
		timeout = 10
	}
	var lastErr error

	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
	}

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Duration(retryInterval) * time.Second)
		}

		req, err := http.NewRequest("GET", subUrl, nil)
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("User-Agent", "clash.meta")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			lastErr = fmt.Errorf("订阅链接: %s 返回状态码: %d", subUrl, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("读取订阅链接: %s 数据错误: %v", subUrl, err)
			continue
		}
		return body, nil
	}

	return nil, fmt.Errorf("重试%d次后失败: %v", maxRetries, lastErr)
}
