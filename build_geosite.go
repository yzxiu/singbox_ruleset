package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("GITHUB_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func fetch(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func get(downloadURL *string) ([]byte, error) {
	log.Info("download ", *downloadURL)
	response, err := http.Get(*downloadURL)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func download(release *github.RepositoryRelease) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat"
	})
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == "dlc.dat.sha256sum"
	})
	if geositeAsset == nil {
		return nil, E.New("geosite asset not found in upstream release ", release.Name)
	}
	if geositeChecksumAsset == nil {
		return nil, E.New("geosite checksum not found in upstream release ", release.Name)
	}
	data, err := get(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := get(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("checksum mismatch")
	}
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)
		for _, domain := range vGeositeEntry.Domain {
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}
			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				if strings.Contains(domain.Value, ".") {
					domains = append(domains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: "." + domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					if strings.Contains(domain.Value, ".") {
						attributeDomains = append(attributeDomains, geosite.Item{
							Type:  geosite.RuleTypeDomain,
							Value: domain.Value,
						})
					}
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: "." + domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

type filteredCodePair struct {
	code    string
	badCode string
}

func filterTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var badCodeList []filteredCodePair
	var filteredCodeMap []string
	var mergedCodeMap []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		leftParts := strings.Split(codeParts[0], "-")
		var lastName string
		if len(leftParts) > 1 {
			lastName = leftParts[len(leftParts)-1]
		}
		if lastName == "" {
			lastName = codeParts[0]
		}
		if lastName == codeParts[1] {
			delete(data, code)
			filteredCodeMap = append(filteredCodeMap, code)
			continue
		}
		if "!"+lastName == codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		} else if lastName == "!"+codeParts[1] {
			badCodeList = append(badCodeList, filteredCodePair{
				code:    codeParts[0],
				badCode: code,
			})
		}
	}
	for _, it := range badCodeList {
		badList := data[it.badCode]
		if badList == nil {
			log.Warn("bad list not found: ", it.badCode)
			continue
		}
		delete(data, it.badCode)
		newMap := make(map[geosite.Item]bool)
		for _, item := range data[it.code] {
			newMap[item] = true
		}
		for _, item := range badList {
			delete(newMap, item)
		}
		newList := make([]geosite.Item, 0, len(newMap))
		for item := range newMap {
			newList = append(newList, item)
		}
		data[it.code] = newList
		mergedCodeMap = append(mergedCodeMap, it.badCode)
	}
	sort.Strings(filteredCodeMap)
	sort.Strings(mergedCodeMap)
	if len(filteredCodeMap) > 0 {
		log.Info("filtered tags: ", strings.Join(filteredCodeMap, ", "))
	}
	if len(mergedCodeMap) > 0 {
		log.Info("merged tags: ", strings.Join(mergedCodeMap, ", "))
	}
}

func mergeTags(data map[string][]geosite.Item) {
	var codeList []string
	for code := range data {
		codeList = append(codeList, code)
	}
	var cnCodeList []string
	for _, code := range codeList {
		codeParts := strings.Split(code, "@")
		if len(codeParts) != 2 {
			continue
		}
		if codeParts[1] != "cn" {
			continue
		}
		if !strings.HasPrefix(codeParts[0], "category-") {
			continue
		}
		if strings.HasSuffix(codeParts[0], "-cn") || strings.HasSuffix(codeParts[0], "-!cn") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	for _, code := range codeList {
		if !strings.HasPrefix(code, "category-") {
			continue
		}
		if !strings.HasSuffix(code, "-cn") {
			continue
		}
		if strings.Contains(code, "@") {
			continue
		}
		cnCodeList = append(cnCodeList, code)
	}
	newMap := make(map[geosite.Item]bool)
	if cnBase, ok := data["geolocation-cn"]; ok {
		for _, item := range cnBase {
			newMap[item] = true
		}
	}
	for _, code := range cnCodeList {
		for _, item := range data[code] {
			newMap[item] = true
		}
	}
	newList := make([]geosite.Item, 0, len(newMap))
	for item := range newMap {
		newList = append(newList, item)
	}
	data["geolocation-cn"] = newList
	data["cn"] = append(newList, geosite.Item{
		Type:  geosite.RuleTypeDomainSuffix,
		Value: "cn",
	})
	if len(cnCodeList) > 0 {
		log.Info("merged cn categories: ", strings.Join(cnCodeList, ", "))
	}
}

func saveRuleSet(outputDir, code string, domains []geosite.Item) error {
	// 创建目录
	dir := filepath.Join(outputDir, code)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// 编译为规则
	defaultRule := geosite.Compile(domains)

	// 创建 PlainRuleSet 用于 JSON 和 SRS
	var headlessRule option.DefaultHeadlessRule
	headlessRule.Domain = defaultRule.Domain
	headlessRule.DomainSuffix = defaultRule.DomainSuffix
	headlessRule.DomainKeyword = defaultRule.DomainKeyword
	headlessRule.DomainRegex = defaultRule.DomainRegex

	var plainRuleSet option.PlainRuleSet
	plainRuleSet.Rules = []option.HeadlessRule{
		{
			Type:           C.RuleTypeDefault,
			DefaultOptions: headlessRule,
		},
	}

	// 保存 JSON 文件
	jsonPath := filepath.Join(dir, code+".json")
	jsonFile, err := os.Create(jsonPath)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(jsonFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plainRuleSet); err != nil {
		jsonFile.Close()
		return err
	}
	jsonFile.Close()

	// 保存 SRS 文件
	srsPath := filepath.Join(dir, code+".srs")
	srsFile, err := os.Create(srsPath)
	if err != nil {
		return err
	}
	err = srs.Write(srsFile, plainRuleSet, false)
	srsFile.Close()
	if err != nil {
		return err
	}

	// 创建 README
	readmePath := filepath.Join(dir, "README.md")
	readme, err := os.Create(readmePath)
	if err != nil {
		return err
	}
	defer readme.Close()

	writer := bufio.NewWriter(readme)
	writer.WriteString("# " + code + "\n\n")
	writer.WriteString("#### 规则链接\n\n")
	writer.WriteString("**Github**\n")
	writer.WriteString("https://raw.githubusercontent.com/yzxiu/singbox_ruleset/main/sing-geosite/" + code + "/" + code + ".srs\n\n")
	writer.WriteString("**CDN**\n")
	writer.WriteString("https://cdn.jsdelivr.net/gh/yzxiu/singbox_ruleset@main/sing-geosite/" + code + "/" + code + ".srs\n")
	writer.Flush()

	return nil
}

func generate(release *github.RepositoryRelease, outputDir string) error {
	log.Info("downloading geosite data from v2fly/domain-list-community...")
	vData, err := download(release)
	if err != nil {
		return err
	}
	log.Info("download complete, size: ", len(vData), " bytes")

	log.Info("parsing geosite data...")
	domainMap, err := parse(vData)
	if err != nil {
		return err
	}
	log.Info("parsed ", len(domainMap), " categories")

	log.Info("filtering tags...")
	filterTags(domainMap)

	log.Info("merging cn tags...")
	mergeTags(domainMap)

	// 清理并创建输出目录
	os.RemoveAll(outputDir)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	log.Info("generating rule sets...")
	count := 0
	for code, domains := range domainMap {
		if len(domains) == 0 {
			continue
		}

		if err := saveRuleSet(outputDir, code, domains); err != nil {
			log.Warn("failed to save rule set ", code, ": ", err)
			continue
		}
		count++

		if count%100 == 0 {
			log.Info("generated ", count, " rule sets...")
		}
	}

	log.Info("successfully generated ", count, " rule sets in ", outputDir)
	return nil
}

func main() {
	log.Info("starting geosite build process...")

	release, err := fetch("v2fly/domain-list-community")
	if err != nil {
		log.Fatal("failed to fetch latest release: ", err)
	}
	log.Info("latest release: ", *release.Name)

	err = generate(release, "sing-geosite")
	if err != nil {
		log.Fatal(err)
	}

	log.Info("geosite build complete!")
}
