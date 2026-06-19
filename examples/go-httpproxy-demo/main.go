/*
go-httpproxy-demo is an example for HTTP and HTTPS web proxy.

Connect through HTTP proxy to HTTP:
curl -x "http://test:1234@localhost:8080" http://httpbin.org/get?a=b

Connect through HTTP proxy to HTTPS with MITM:
curl --insecure -x "http://test:1234@localhost:8080" https://httpbin.org/get?a=b

Connect through HTTPS proxy to HTTP:
curl --proxy-insecure -x "https://test:1234@localhost:8443" http://httpbin.org/get?a=b

Connect through HTTPS proxy to HTTPS with MITM:
curl --proxy-insecure --insecure -x "https://test:1234@localhost:8443" https://httpbin.org/get?a=b
*/
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/orkunkaraduman/go-httpproxy"
)

var logErr = log.New(os.Stderr, "ERR: ", log.LstdFlags)

func OnError(ctx *httpproxy.Context, where string,
	err *httpproxy.Error, opErr error) {
	// Log errors.
	logErr.Printf("%s: %s [%s]", where, err, opErr)
}

func OnAccept(ctx *httpproxy.Context, w http.ResponseWriter,
	r *http.Request) bool {
	// Handle local request has path "/info"
	if r.Method == "GET" && !r.URL.IsAbs() && r.URL.Path == "/info" {
		w.Write([]byte("This is go-httpproxy."))
		return true
	}
	return false
}

func OnAuth(ctx *httpproxy.Context, authType string, user string, pass string) bool {
	// Auth test user.
	if user == "test" && pass == "1234" {
		return true
	}
	return false
}

func OnConnect(ctx *httpproxy.Context, host string) (
	ConnectAction httpproxy.ConnectAction, newHost string) {
	// Apply "Man in the Middle" to all ssl connections. Never change host.
	return httpproxy.ConnectMitm, host
}

func OnRequest(ctx *httpproxy.Context, req *http.Request) (
	resp *http.Response) {
	// Log proxying requests.
	log.Printf("INFO: Proxy %d %d: %s %s", ctx.SessionNo, ctx.SubSessionNo, req.Method, req.URL.String())
	return
}

func OnResponse(ctx *httpproxy.Context, req *http.Request,
	resp *http.Response) {
	// Add header "Via: go-httpproxy".
	resp.Header.Add("Via", "go-httpproxy")
}

func main() {
	log.SetOutput(os.Stdout)
	log.Print("Started")

	sigChan := make(chan os.Signal)
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGTERM)

	// Create a new proxy with default certificate pair.
	prx, _ := httpproxy.NewProxy()

	// Set proxy handlers.
	prx.OnError = OnError
	prx.OnAccept = OnAccept
	prx.OnAuth = OnAuth
	prx.OnConnect = OnConnect
	prx.OnRequest = OnRequest
	prx.OnResponse = OnResponse
	//prx.MitmChunked = false

	server := &http.Server{
		Addr:         ":8080",
		Handler:      prx,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	listenErrChan := make(chan error)
	go func() {
		listenErrChan <- server.ListenAndServe()
	}()
	log.Printf("Listening HTTP %s", server.Addr)

	cert, _ := tls.X509KeyPair(httpproxy.DefaultCaCert, httpproxy.DefaultCaKey)
	serverHTTPS := &http.Server{
		Addr:         ":8443",
		Handler:      prx,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		TLSConfig: &tls.Config{
			MinVersion:               tls.VersionSSL30,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			PreferServerCipherSuites: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			Certificates: []tls.Certificate{cert},
		},
	}
	listenHTTPSErrChan := make(chan error)
	go func() {
		listenHTTPSErrChan <- serverHTTPS.ListenAndServeTLS("", "")
	}()
	log.Printf("Listening HTTPS %s", serverHTTPS.Addr)

mainloop:
	for {
		select {
		case <-sigChan:
			break mainloop
		case listenErr := <-listenErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			log.Fatal(listenErr)
		case listenErr := <-listenHTTPSErrChan:
			if listenErr != nil && listenErr == http.ErrServerClosed {
				break mainloop
			}
			log.Fatal(listenErr)
		}
	}

	shutdown := func(srv *http.Server, wg *sync.WaitGroup) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		srv.SetKeepAlivesEnabled(false)
		if err := srv.Shutdown(ctx); err == context.DeadlineExceeded {
			log.Printf("Force shutdown %s", srv.Addr)
		} else {
			log.Printf("Graceful shutdown %s", srv.Addr)
		}
		wg.Done()
	}

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go shutdown(server, wg)
	wg.Add(1)
	go shutdown(serverHTTPS, wg)
	wg.Wait()

	log.Println("Finished")
}
