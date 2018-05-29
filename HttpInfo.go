package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/axgle/mahonia"
	"github.com/saintfish/chardet"
	"io/ioutil"
	//"log"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var port, timeout, thread int
var beginip, endip, file string

func init() {

	flag.IntVar(&port, "p", 80, "Port")
	flag.IntVar(&timeout, "o", 5, "Timeout settings")
	flag.IntVar(&thread, "t", 10, "Thread worker to scan")
	flag.StringVar(&beginip, "b", "", "Begin IP")
	flag.StringVar(&endip, "e", "", "End IP")
	flag.StringVar(&file, "i", "", "Input from file, beginip and endip or file must be have one")

	// 修改提示信息
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\nUsage: %s -p 80 -b 192.168.1.1 -e 192.168.1.254 -t 10 -o 5\n\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
}

//IP字段转数字
func StringIpToInt(ipstring string) int {
	ipSegs := strings.Split(ipstring, ".")
	var ipInt int = 0
	var pos uint = 24
	for _, ipSeg := range ipSegs {
		tempInt, _ := strconv.Atoi(ipSeg)
		tempInt = tempInt << pos
		ipInt = ipInt | tempInt
		pos -= 8
	}
	return ipInt
}

//数字回复IP
func IpIntToString(ipInt int) string {
	ipSegs := make([]string, 4)
	var len int = len(ipSegs)
	buffer := bytes.NewBufferString("")
	for i := 0; i < len; i++ {
		tempInt := ipInt & 0xFF
		ipSegs[len-i-1] = strconv.Itoa(tempInt)
		ipInt = ipInt >> 8
	}
	for i := 0; i < len; i++ {
		buffer.WriteString(ipSegs[i])
		if i < len-1 {
			buffer.WriteString(".")
		}
	}
	return buffer.String()
}

//获取文本编码
func TextDetector(body []byte) (v string) {
	detector := chardet.NewTextDetector()
	result, err := detector.DetectBest(body)
	if err == nil {
		v = result.Charset
	}
	return v
}

//转换文本编码
func ConvertToString(src string, srcCode string, tagCode string) string {
	srcCoder := mahonia.NewDecoder(srcCode)
	srcResult := srcCoder.ConvertString(src)
	tagCoder := mahonia.NewDecoder(tagCode)
	_, cdata, _ := tagCoder.Translate([]byte(srcResult), true)
	result := string(cdata)
	return result
}

//文件读取
func readfile(dir string) ([]byte, error) {
	f, err := os.Open(dir)
	if err != nil {
		fmt.Println("File load Error!\n")
	}
	return ioutil.ReadAll(f)
}

//获取Web信息
func GetWebInfo(ip string, port int, timeout_set int) (string, error) {
	var domain, websever, result string = "", "", ""
	if ip[0:7] == "http://" || ip[0:8] == "https://" {
		domain = strings.Replace(strings.Split(ip, "//")[1], "/", "", -1)
	} else {
		domain = strings.Replace(ip, "/", "", 1)
		ip = "http://" + ip
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //跳过证书校验
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(timeout_set) * time.Second,
	}
	req, err := http.NewRequest("GET", ip+":"+strconv.Itoa(port), nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.139 Safari/537.36") //UA设定
	res, err := client.Do(req)
	if err == nil {
		data, err := ioutil.ReadAll(res.Body)
		checkError(err)
		body := strings.Replace(string(data), "\"", "'", -1) //将所有response中的"转义为',避免结果入库时存在争议
		charset := TextDetector(data)
		body = ConvertToString(body, charset, "utf-8")

		regex1 := regexp.MustCompile("<title>(.*?)</title>")
		titles := regex1.FindAllStringSubmatch(body, -1)

		WebSeverValue := res.Header["Server"]
		if len(WebSeverValue) < 1 {
			websever = ""
		} else {
			websever = WebSeverValue[0]
		}

		if len(titles) < 1 {
			//未取得Title字段
			result = "\"" + domain + "\",\"" + strconv.Itoa(port) + "\",\"" + websever + "\",\"\",\"" // + body + "\""
		} else {
			result = "\"" + domain + "\",\"" + strconv.Itoa(port) + "\",\"" + websever + "\",\"" + titles[0][1] + "\",\"" // + body + "\""
		}
	}

	return result, err
}

func run(ips []string, tnum int, task int, wg *sync.WaitGroup) {
	for i := tnum*task + 1; i <= (tnum*task)+task; i++ {
		ips[i-1] = strings.TrimSpace(ips[i-1])
		//fmt.Println(strconv.Itoa(i) + " " + ips[i-1] + " Scan")
		result, err := GetWebInfo(ips[i-1], port, timeout)
		if err == nil {
			fmt.Println(result)
		}
		wg.Done()
	}
}

func checkError(err error) {
	//if err != nil {
	//log.Fatalf("Error: %v", err)
	//	continue
}

func main() {
	args := os.Args
	if len(args) < 2 {
		flag.Usage()
	} else {
		runtime.GOMAXPROCS(runtime.NumCPU())
		var ips []string
		if file != "" {
			f, err := readfile(file)
			if err != nil {
				err.Error()
			}
			ips = strings.Split(string(f), "\n")
		}
		if beginip != "" && endip != "" {
			for i := StringIpToInt(beginip); i < StringIpToInt(endip); i++ {
				ips = append(ips, IpIntToString(i))
			}
		}

		lens := len(ips)
		//fmt.Println(lens)
		//每线程任务数
		task := lens / thread
		wg := sync.WaitGroup{}
		wg.Add(lens)
		for i := 0; i < thread; i++ {
			go run(ips, i, task, &wg)
		}
		wg.Wait()
		//GetWebInfo("http://stock.10jqka.com.cn", port, 2)
	}
}
