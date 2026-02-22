package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/ipinfo/go/v2/ipinfo"
)

const (
	token = "PASTE YOUR TOKEN HERE"
)

type discordMessage struct {
	Content string `json:"content"`
}

func main() {
	listener, err := net.Listen("tcp", ":23")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	file, err := os.OpenFile("hp.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0664)
	if err != nil {
		log.Println(err)
	}
	defer file.Close()

	mw := io.MultiWriter(os.Stdout, file)
	log.SetOutput(mw)

	fmt.Print(color.GreenString("Honeypot active! \n"))

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("connection error")
			continue
		}
		go handleAttack(conn)
	}
}

func sendWebhook(msg string) {
	webhookURL := "PASTE HERE YOUR WEBHOOK"

	payload := discordMessage{
		Content: msg,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Println("json error", err)
		return
	}

	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Println("send error", err)
		return
	}
	defer resp.Body.Close()
}

func handleAttack(conn net.Conn) {
	defer conn.Close()

	remoteAddr := conn.RemoteAddr().String()
	host, _, _ := net.SplitHostPort(remoteAddr)
	client := ipinfo.NewClient(nil, nil, token)
	info, err := client.GetIPInfo(net.ParseIP(host))

	if err != nil {
		log.Println(err)
	}

	alertMsg := fmt.Sprintf("**New connection**\nIP: `%s`\nCountry: %s\nCity: %s\n@everyone", host, info.Country, info.City)
	go sendWebhook(alertMsg)

	log.Print(host, "\n",
		"Country: ", info.Country, "\n",
		"City: ", info.City)

	conn.SetDeadline(time.Now().Add(60 * time.Second))
	conn.Write([]byte("Router tplink 1.5\r\n"))
	conn.Write([]byte("Login: "))

	scanner := bufio.NewScanner(conn)

	if scanner.Scan() {
		login := strings.TrimSpace(scanner.Text())
		log.Printf("[%s] login attempt %s", remoteAddr, login)
	}

	conn.Write([]byte("Password: "))
	if scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		log.Printf("[%s] password attempt %s", remoteAddr, password)
	}

	time.Sleep(2 * time.Second)
	conn.Write([]byte("\r\nroot@tplink-router: "))

	for scanner.Scan() {
		cmd := strings.TrimSpace(scanner.Text())
		conn.SetDeadline(time.Now().Add(60 * time.Second))
		log.Printf("[%s] cmd: %s", remoteAddr, cmd)

		parts := strings.Fields(cmd)
		if len(parts) == 0 {
			continue
		}
		command := parts[0]
		args := parts[1:]

		switch command {
		case "exit":
			return
		case "sh", "shell", "/bin/sh", "/bin/bash":
			conn.Write([]byte("\r\nroot@tplink-router: "))
		case "uname":
			conn.Write([]byte("Linux tplink-router 3.4.103 #1 SMP armv7l GNU/Linux\r\nroot@tplink-router: "))
		case "id":
			conn.Write([]byte("uid=0(root) gid=0(root) groups=0(root)\r\nroot@tplink-router: "))
		case "echo":
			if len(args) == 0 {
				conn.Write([]byte("                                                                 "))
				conn.Write([]byte("                                                                 \r\nroot@tplink-router: "))
			} else {
				echo := args[0]
				conn.Write([]byte(echo + "\r\nroot@tplink-router: "))
			}
		case "ls":
			conn.Write([]byte("config.cfg  pass.txt\r\nroot@tplink-router: "))
		case "cat":
			if len(args) == 0 {
				conn.Write([]byte("Usage: cat <filename>\r\nroot@tplink-router: "))
			} else {
				filename := args[0]
				switch filename {
				case "pass.txt":
					conn.Write([]byte("SzOOk:R18Vj1SJ\r\nroot@tplink-router: "))
				case "config.cfg":
					conn.Write([]byte("server=127.0.0.1\r\nroot@tplink-router: "))
				default:
					conn.Write([]byte("cat: " + filename + ": No such file or directory\r\nroot@tplink-router: "))
				}
			}
		case "whoami":
			conn.Write([]byte("root\r\nroot@tplink-router:"))
		case "ping":
			if len(args) == 0 {
				conn.Write([]byte("ping: usage error: Destination address required\r\nroot@tplink-router: "))
			} else {
				url := args[0]
				conn.Write([]byte("PING " + url + " (" + url + ")" + "56(84) bytes of data.\r\n"))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("64 bytes from " + url + " icmp_seq=1 ttl=255 time=14.0 ms\r\n"))
				time.Sleep(1 * time.Second)
				conn.Write([]byte("64 bytes from " + url + " icmp_seq=2 ttl=255 time=12.4 ms\r\n"))
				time.Sleep(1 * time.Second)
				conn.Write([]byte("64 bytes from " + url + " icmp_seq=3 ttl=255 time=13.7 ms\r\n"))
				time.Sleep(1 * time.Second)
				conn.Write([]byte("64 bytes from " + url + " icmp_seq=4 ttl=255 time=11.9 ms\r\n"))
				time.Sleep(200 * time.Millisecond)
				conn.Write([]byte("--- " + url + " ping statistics ---\r\n"))
				conn.Write([]byte("4 packets transmitted, 4 received, 0% packet loss, time 3610ms\r\n"))
				conn.Write([]byte("rtt min/avg/max/mdev = 12.812/13.647/14.609/0.638 ms\r\nroot@tplink-router: "))

			}
		case "wget":
			if len(args) == 0 {
				conn.Write([]byte("wget: missing URL\r\nUsage: wget [OPTION]... [URL]...\r\n \r\nTry `wget --help' for more options.\r\nroot@tplink-router: "))
			} else {
				url := args[0]
				log.Printf(color.RedString("malware detected [%s] %s", remoteAddr, url))
				alertMalware := fmt.Sprintf("**Malware detected**\nURL: %s\n@everyone", url)
				go sendWebhook(alertMalware)

				timestamp := time.Now().Format("2006-01-02 15:04:05")
				conn.Write([]byte("--" + timestamp + "--  " + url + "\r\n"))
				conn.Write([]byte("Resolving " + url + " (" + url + ")" + " 162.185.23.58 " + "\r\n"))
				conn.Write([]byte("Connecting to " + url + " (" + url + ")" + "|162.185.23.58|:80 ... connected.\r\n"))
				conn.Write([]byte("HTTP request sent, awaiting response... 200 OK\r\n"))
				conn.Write([]byte("Length: 11064 (11K)\r\n"))
				conn.Write([]byte("Saving file\r\n"))
				time.Sleep(500 * time.Millisecond)
				conn.Write([]byte("\r\nfile.sh                          100%[================================================================>]  10.80K  --.-KB/s    in 0s\r\n"))
				conn.Write([]byte("\r\n" + timestamp + "(1.04 GB/s) - file saved [11064/11064]"))
				conn.Write([]byte("\r\nroot@tplink-router: "))
			}
		default:
			conn.Write([]byte(command + ": command not found\r\nroot@tplink-router: "))
		}
	}
}


