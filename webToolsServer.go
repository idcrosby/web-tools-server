package main

import (
	"bytes"
	"flag"
	"fmt"
	"github.com/idcrosby/web-tools"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"text/template"
	"time"
)

var InfoLog *log.Logger
var ErrorLog *log.Logger
var Verbose bool

func main() {
	fmt.Println("running server...")

	// Define flags
	flag.BoolVar(&Verbose, "verbose", false, "Turn on verbose logging.")
	flag.Parse()

	// init loggers
	InfoLog = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime)
	ErrorLog = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime)

	http.HandleFunc("/", errorHandler(defaultHandler))
	http.HandleFunc("/base64Encode", errorHandler(base64EncodeHandler))
	http.HandleFunc("/base64Decode", errorHandler(base64DecodeHandler))
	http.HandleFunc("/validateJson", errorHandler(validateJsonHandler))
	http.HandleFunc("/md5Hash", errorHandler(md5HashHandler))
	http.HandleFunc("/sha1Hash", errorHandler(sha1HashHandler))
	http.HandleFunc("/convertTimeToEpoch", errorHandler(convertTimeToEpochHandler))
	http.HandleFunc("/convertTimeFromEpoch", errorHandler(convertTimeFromEpochHandler))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8087"
	}
	fmt.Println("PORT:", port)
	http.ListenAndServe(":" + port, nil)
}

func defaultHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("defaultHandler called")
	//var mainTemplate, err = template.ParseFiles("main.html")
	var webToolsTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	//mainTemplate.Execute(rw, nil)
	webToolsTemplate.Execute(rw, nil)
}

func base64EncodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64EncodeHandler called")
	encode := retrieveParam(req, "data")
	if (len(encode) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	encoded := myTools.Base64Encode([]byte(encode))
	//rw.Write([]byte(encoded))
	var data = Data{Result: encoded}
	var resultTemplate, err = template.ParseFiles("webToolsResult.html")
	check(err)
	resultTemplate.Execute(rw, data) 
}

func base64DecodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64DecodeHandler called")

}

func validateJsonHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("validateJsonHandler called")

}

func md5HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("md5HashHandler called")

}

func sha1HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("sha1HashHandler called")

}

func convertTimeToEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeToEpochHandler called")

}

func convertTimeFromEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeFromEpochHandler called")

}

// Error Handler Wrapper
func errorHandler(fn http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if Verbose {
			InfoLog.Println(string(requestAsString(req)[:]))
		}
		defer func() {
			if e, ok := recover().(error); ok {
				w.WriteHeader(500)
				ErrorLog.Println(e)
			}
		}()
		fn(w, req)
	}
}

func check(err error) { if err != nil { panic(err) } }

// Retreive parameters passed in via query or post body
func retrieveParam(req *http.Request, param string) string {
	params, err := url.ParseQuery(req.URL.RawQuery)
	check(err)
	value := params[param]

	if len(value) < 1 {
		return ""
	} else {
		return value[0]
	}
	// TODO read from POST body
}

// Create a string which contains all important request data
func requestAsString(request *http.Request) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("\n")
	buffer.WriteString("Current Time: ")
	buffer.WriteString(time.Now().String())
	buffer.WriteString("\n")
	requestBytes, err := httputil.DumpRequest(request, true)
	check(err)
	buffer.Write(requestBytes)

	return buffer.Bytes()
}