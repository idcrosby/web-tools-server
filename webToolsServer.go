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
	"html/template"
	"time"
)

var InfoLog *log.Logger
var ErrorLog *log.Logger
var Verbose bool

// Constants

var homeHtml = "resources/html/webToolsHome.html"
var base64Html = "resources/html/webToolsBase64.html"
var jsonHtml = "resources/html/webToolsJson.html"
var md5Html = "resources/html/webToolsMd5.html"
var sha1Html = "resources/html/webToolsSha1.html"
var timeHtml = "resources/html/webToolsTime.html"

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

	// Serve CSS/JS files
	http.Handle("/resources/", http.StripPrefix("/resources/", http.FileServer(http.Dir("resources"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8087"
	}
	fmt.Println("PORT:", port)
	http.ListenAndServe(":" + port, nil)
}

func defaultHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("defaultHandler called")
	var webToolsTemplate, err = template.ParseFiles(homeHtml)
	check(err)
	var responseData = ResponseData{}
	webToolsTemplate.Execute(rw, responseData)
}

// TODO Merge these handlers?
func base64EncodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64EncodeHandler called")
	encode := retrieveParam(req, "data")

	var responseData = ResponseData{}	
	if (len(encode) != 0) {
		encoded := myTools.Base64Encode([]byte(encode), false)
		responseData = ResponseData{Input: encode, Output: encoded, Field: "EncodeDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(base64Html)
	check(err)
	resultTemplate.Execute(rw, responseData) 
}

func base64DecodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64DecodeHandler called")
	decode := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(decode) != 0) {
		decoded := myTools.Base64Decode(decode, false)
		responseData = ResponseData{Input: decode, Output: string(decoded), Field: "DecodeDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(base64Html)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func validateJsonHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("validateJsonHandler called")
	input := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(input) != 0) {
		json, err := myTools.ValidateJson([]byte(input))
		if (err != nil) {
			json = []byte(err.Error())
		}
		responseData = ResponseData{Input: input, Output: string(json), Field: "JsonDiv", Valid: (err == nil)}
	}
	var resultTemplate, err = template.ParseFiles(jsonHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func md5HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("md5HashHandler called")
	input := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(input) != 0) {
		hash := myTools.Md5Hash([]byte(input))
		responseData = ResponseData{Input: input, Output: hash, Field: "Md5HashDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(md5Html)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func sha1HashHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("sha1HashHandler called")
	input := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(input) != 0) {
		hash := myTools.Sha1Hash([]byte(input))
		responseData = ResponseData{Input: input, Output: hash, Field: "Sha1HashDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(sha1Html)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func convertTimeToEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeToEpochHandler called")
	var responseData = ResponseData{}
	var timeString string
	// Check if long format was passed in
	if (len(retrieveParam(req, "year")) != 0) {
		year := req.FormValue("year")
		month := req.FormValue("month")
		day := req.FormValue("day")
		hour := req.FormValue("hour")
		minute := req.FormValue("minute")
		second := req.FormValue("second")
		// timeZone := req.FormValue("timeZone")

		timeString = year + "-" + month + "-" + day + " " + hour + ":" + minute + ":" + second + " +0000 GMT"
	} else {
		timeString = retrieveParam(req, "data")
	}

	if (len(timeString) != 0) {
		myTime, _ := time.Parse("2006-01-02 15:04:05 -0700 MST", timeString)
		epochTime := myTools.ConvertTimeToEpoch(myTime)
		responseData = ResponseData{Input: timeString, Output: strconv.FormatInt(epochTime, 10), Field: "TimeToEpochDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(timeHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func convertTimeFromEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeFromEpochHandler called")
	input := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(input) != 0) {
		epochTime, _ := strconv.ParseInt(input, 10, 64	)
		time := myTools.ConvertTimeFromEpoch(epochTime)
		responseData = ResponseData{Input: input, Output: time.String(), Field: "TimeFromEpochDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(timeHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
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

// type Data struct {
// 	EncodeValid, DecodeValid, JsonValid, Md5Valid, Sha1Valid, EpochTimeValid, ReadableTimeValid bool
// 	EncodeResult, DecodeResult, JsonResult, Md5Result, Sha1Result, EpochTimeResult, ReadableTimeResult string
// }

type ResponseData struct {
	Input, Output, Field string
	Valid bool
}