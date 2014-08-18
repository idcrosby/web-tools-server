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
	"strconv"
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
	var data = Data{}
	//mainTemplate.Execute(rw, nil)
	webToolsTemplate.Execute(rw, data)
}

// TODO Merge these handlers
func base64EncodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64EncodeHandler called")
	encode := retrieveParam(req, "data")
	var data = Data{}
	if (len(encode) == 0) {
		ErrorLog.Println("No data found.")
		// rw.WriteHeader(400)
		data = Data{EncodeResult: "", EncodeValid: false}
		// return
	} else {
		encoded := myTools.Base64Encode([]byte(encode))
		//rw.Write([]byte(encoded))
		data = Data{EncodeResult: encoded, EncodeValid: true}
	}	
	// var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data) 
}

func base64DecodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64DecodeHandler called")
	decode := retrieveParam(req, "data")
	if (len(decode) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	decoded := myTools.Base64Decode(decode)
	var data = Data{DecodeResult: string(decoded), DecodeValid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)
}

func validateJsonHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("validateJsonHandler called")
	input := retrieveParam(req, "data")
	if (len(input) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	json := myTools.ValidateJson([]byte(input))
	var data = Data{JsonResult: string(json), JsonValid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)

}

func md5HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("md5HashHandler called")
	input := retrieveParam(req, "data")
	if (len(input) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	hash := myTools.Md5Hash([]byte(input))
	var data = Data{Md5Result: hash, Md5Valid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)
}

func sha1HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("sha1HashHandler called")
	input := retrieveParam(req, "data")
	if (len(input) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	hash := myTools.Sha1Hash([]byte(input))
	var data = Data{Sha1Result: hash, Sha1Valid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)
}

func convertTimeToEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeToEpochHandler called")
	input := retrieveParam(req, "data")
	if (len(input) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	myTime, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", string(input))
	epochTime := myTools.ConvertTimeToEpoch(myTime)
	var data = Data{EpochTimeResult: strconv.FormatInt(epochTime, 10), EpochTimeValid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)
}

func convertTimeFromEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeFromEpochHandler called")
	input := retrieveParam(req, "data")
	if (len(input) == 0) {
		ErrorLog.Println("No data found.")
		rw.WriteHeader(400)
		return
	}
	epochTime, _ := strconv.ParseInt(input, 10, 64	)
	time := myTools.ConvertTimeFromEpoch(epochTime)
	var data = Data{ReadableTimeResult: time.String(), ReadableTimeValid: true}
	var resultTemplate, err = template.ParseFiles("webToolsForm.html")
	check(err)
	resultTemplate.Execute(rw, data)
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

type Data struct {
	EncodeValid, DecodeValid, JsonValid, Md5Valid, Sha1Valid, EpochTimeValid, ReadableTimeValid bool
	EncodeResult, DecodeResult, JsonResult, Md5Result, Sha1Result, EpochTimeResult, ReadableTimeResult string
}