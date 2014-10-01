package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/idcrosby/web-tools"
	"github.com/idcrosby/goProxyGo"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"html/template"
	"time"
)

var InfoLog *log.Logger
var ErrorLog *log.Logger
var Verbose bool

// Constants

var OUTPUT_DIR = "output/"

var homeHtml = "resources/html/webToolsHome.html"
var encodingHtml = "resources/html/webToolsEncoding.html"
var jsonHtml = "resources/html/webToolsJson.html"
var compareJsonHtml = "resources/html/webToolsCompareJson.html"
var hashingHtml = "resources/html/webToolsHashing.html"
var timeHtml = "resources/html/webToolsTime.html"
var contactHtml = "resources/html/webToolsContact.html"
var apiHtml = "resources/html/webToolsAPI.html"
var searchHtml = "resources/html/webToolsSearch.html"
var proxyHtml = "resources/html/webToolsProxy.html"

func main() {

	var logFileName string
	var writer io.Writer

	// Define flags
	flag.BoolVar(&Verbose, "verbose", false, "Turn on verbose logging.")
	flag.StringVar(&logFileName, "logFile", "", "Verbose log to file.")
	flag.Parse()

	// init loggers
	writer = os.Stdout
	if len(logFileName) > 0 {
		logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("Error opening log file: ", err)
		} else {
			defer logFile.Close()
			writer = bufio.NewWriter(logFile)
		}
	}

	InfoLog = log.New(writer, "INFO: ", log.LstdFlags)
	ErrorLog = log.New(writer, "ERROR: ", log.LstdFlags)

	http.HandleFunc("/", errorHandler(defaultHandler))
	http.HandleFunc("/encoding", errorHandler(base64EncodeHandler))
	http.HandleFunc("/base64Decode", errorHandler(base64DecodeHandler))
	http.HandleFunc("/urlEncode", errorHandler(urlEncodeHandler))
	http.HandleFunc("/validateJson", errorHandler(validateJsonHandler))
	http.HandleFunc("/compareJson", errorHandler(compareJsonHandler))
	http.HandleFunc("/hashing", errorHandler(hashingHandler))
	http.HandleFunc("/convertTimeToEpoch", errorHandler(convertTimeToEpochHandler))
	http.HandleFunc("/convertTimeFromEpoch", errorHandler(convertTimeFromEpochHandler))
	http.HandleFunc("/contact", errorHandler(contactHandler))
	http.HandleFunc("/api", errorHandler(apiHandler))
	http.HandleFunc("/search", errorHandler(searchHandler))
	http.HandleFunc("/proxy", errorHandler(proxyHandler))

	// Serve CSS/JS files
	http.Handle("/resources/", http.StripPrefix("/resources/", http.FileServer(http.Dir("resources"))))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8087"
	}
	fmt.Println("Server running on Port:", port)
	http.ListenAndServe(":" + port, nil)
}

func defaultHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("defaultHandler called")
	var webToolsTemplate, err = template.ParseFiles(homeHtml)
	check(err)
	var responseData = ResponseData{}
	webToolsTemplate.Execute(rw, responseData)
}

// TODO Merge these handlers
func base64EncodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64EncodeHandler called")
	encode := retrieveParam(req, "data")

	var responseData = ResponseData{}	
	if (len(encode) != 0) {
		encoded := myTools.Base64Encode([]byte(encode), false)
		responseData = ResponseData{Input: encode, Output: encoded, Field: "EncodeDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(encodingHtml)
	check(err)
	resultTemplate.Execute(rw, responseData) 
}

func base64DecodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("base64DecodeHandler called")
	decode := retrieveParam(req, "data")
	var responseData = ResponseData{}
	if (len(decode) != 0) {
		decoded, err := myTools.Base64Decode(decode, false)
		if (err != nil) {
			decoded = []byte(err.Error())
		}
		responseData = ResponseData{Input: decode, Output: string(decoded), Field: "DecodeDiv", Valid: (err == nil)}
	}
	var resultTemplate, err = template.ParseFiles(encodingHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func urlEncodeHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("urlEncodeHandler called")
	var responseData = ResponseData{}	
	var output, field string
	var err error

	data := retrieveParam(req, "encode")
	if len(data) != 0 {
		field = "UrlEncodeDiv"
		output = myTools.UrlEncode(data)
	} else {
		data = retrieveParam(req, "decode")
		if len(data) != 0 {
			output, err = myTools.UrlDecode(data)
			field = "UrlDecodeDiv"
			if (err != nil) {
				output = err.Error()
			}
		}
	}

	responseData = ResponseData{Input: data, Output: output, Field: field, Valid: true}
	var resultTemplate, err2 = template.ParseFiles(encodingHtml)
	check(err2)
	resultTemplate.Execute(rw, responseData) 
}

func validateJsonHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("validateJsonHandler called")

	input := retrieveParam(req, "data")
	pretty, _ := strconv.ParseBool(req.FormValue("pretty"))
	var responseData = ResponseData{}
	if len(input) != 0 {
		var json []byte
		var err error
		whiteListFilter := req.FormValue("whiteListFilter")
		blackListFilter := req.FormValue("blackListFilter")
		if (len(whiteListFilter) != 0 || len(blackListFilter) != 0) {
			if (len(whiteListFilter) != 0) {
				fields := strings.Split(whiteListFilter, ",")
				json, err = myTools.JsonPositiveFilter([]byte(input), fields, pretty)
			} else {
				fields := strings.Split(blackListFilter, ",")
				json, err = myTools.JsonNegativeFilter([]byte(input), fields, pretty)
			}
		} else {
			json, err = myTools.ValidateJson([]byte(input), pretty)
		}
		if err != nil {
			json = []byte(err.Error())
		}
		responseData = ResponseData{Input: input, Output: string(json), Field: "JsonDiv", Valid: (err == nil)}
	}
	var resultTemplate, err = template.ParseFiles(jsonHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func compareJsonHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("compareJsonHandler called")
	var resultTemplate, _ = template.ParseFiles(compareJsonHtml)

	jsonOne := req.FormValue("jsonOne")
	jsonTwo := req.FormValue("jsonTwo")

	if len(jsonOne) < 1 || len(jsonTwo) < 1 {
		responseData := ResponseData{}
		resultTemplate.Execute(rw, responseData)
		return
	}
	result, err := myTools.JsonCompare([]byte(jsonOne), []byte(jsonTwo))

	if err != nil {
		result = []byte(err.Error())
	}
	
	// TODO pass both inputs...?
	responseData := ResponseData{Input: jsonOne, Output: string(result), Field: "JsonDiv", Valid: (err == nil)}

	resultTemplate.Execute(rw, responseData)
}

func hashingHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("hashingHandler called")
	input := retrieveParam(req, "data")
	hashType := req.FormValue("hashType")
	var responseData = ResponseData{}
	if len(input) != 0 {
		var hash string
		if hashType == "Md5" {
			hash = myTools.Md5Hash([]byte(input))
		} else if hashType == "Sha1" {
			hash = myTools.Sha1Hash([]byte(input))
		} else if hashType == "Sha256" {
			hash = myTools.Sha256Hash([]byte(input))
		} else {
			hash = "Error: Unknown hashing type."
		}
		responseData = ResponseData{Input: input, Output: hash, Field: hashType + "HashDiv", Valid: true}
	}
	var resultTemplate, err = template.ParseFiles(hashingHtml)
	check(err)
	resultTemplate.Execute(rw, responseData)
}

func convertTimeToEpochHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("convertTimeToEpochHandler called")
	var responseData = ResponseData{}
	var timeString string
	// Check if long format was passed in
	if (len(req.FormValue("date")) != 0) {
		date := req.FormValue("date")
		hour := req.FormValue("hour")
		minute := req.FormValue("minute")
		second := req.FormValue("second")
		// timeZone := req.FormValue("timeZone")

		timeString = date + " " + hour + ":" + minute + ":" + second + " +0000 GMT"
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

func contactHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("contactHandler called")
	var responseData = ResponseData{}
	now := time.Now()

	message := now.String() + "\n"
	message += "From: "
	message += retrieveParam(req, "sender") + "\n"
	message += retrieveParam(req, "data") + "\n<EOM>\n"

	year, month, day := now.Date()
	// TODO send email ... 
	// ... for now save to file (could also move to DB?)
	fileName := OUTPUT_DIR + strconv.Itoa(year) + "-" + month.String() + "-" + strconv.Itoa(day) + "-messages.txt"

	if _, err := os.Stat(fileName); err != nil {
		_, err = os.Create(fileName)
	}

	f, err := os.OpenFile(fileName, os.O_APPEND, 0644)

	defer f.Close()

	if _, err = f.WriteString(message); err != nil {
		panic(err)
	}

	var resultTemplate, _ = template.ParseFiles(contactHtml)
	resultTemplate.Execute(rw, responseData)
}

func apiHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("apiHandler called")
	t,_ := template.ParseFiles(apiHtml)
	t.Execute(rw, nil)
}

func searchHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("searchHandler called")
	search := retrieveParam(req, "data")
	responseData := ResponseData{Input: search, Output: search, Field: "Search", Valid: true}
	t,_ := template.ParseFiles(searchHtml)
	t.Execute(rw, responseData)
}

func proxyHandler(rw http.ResponseWriter, req *http.Request) {
	InfoLog.Println("proxyHandler called")
	var responseData = ProxyResponse{}
	urlString := req.FormValue("url")
	method := req.FormValue("method")
	reqBody := req.FormValue("reqBody")
	// file := req.FormValue("file")
	file, _, err := req.FormFile("file")

	if err != nil {
		fmt.Printf("Cannot load file...", err)
		// Can't read file / no file
		//check(err)
		// ignore
	}
	
	if len(urlString) > 0 {
		thisUrl, err := url.Parse(urlString)
		check(err)
		var headers map[string][]string
		headers = make(map[string][]string)
		for name, values := range req.Form {
			if subs := strings.Split(name, "headerName"); len(subs) > 1 {
				if len(values[0]) > 0 {
					headers[values[0]] = req.Form["headerValue" + subs[1]]
				}
			}
		}
		var payload []byte
		var bodyReader io.Reader
		if (file != nil) {
			buf := bytes.NewBuffer(nil)
			_, err := io.Copy(buf, file)
			check(err)
			payload = buf.Bytes()
		} else {
			payload = []byte(reqBody)
		}
		bodyReader = bytes.NewReader(payload)
		request := goProxy.DefaultGoProxy.BuildRequest(thisUrl, method, bodyReader, headers)
		if Verbose {
			InfoLog.Println(request)
		}
		var responseString string
		var respHeaders string
		var status string
		var requestHeaders string
		response, err := goProxy.DefaultGoProxy.ExecuteRequest(request)
		if Verbose {
			InfoLog.Println(response)
		}
		if err == nil {
			body, _ := ioutil.ReadAll(response.Body)
			reqDump, _ := httputil.DumpRequestOut(request, false)
			// Strip out top line to get only headers
			requestHeaders = strings.TrimSpace(strings.SplitN(string(reqDump),"\n",2)[1])
			respHeaders = headersToString(response.Header)
			responseString = string(body)
			status = response.Status
		} else {
			responseString = "Error Getting " + urlString
			status = "500"
		}
		responseData = ProxyResponse{InUrl: urlString, InBody: reqBody, Status: status, 
			OutBody: responseString, OutHeaders: respHeaders, InHeaders: requestHeaders,Valid: true}
	}
	
	t,_ := template.ParseFiles(proxyHtml)
	t.Execute(rw, responseData)
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

// Returns a string containing each header on a new line
//   sorted alphabetically
func headersToString(headers map[string][]string) string {
	var buffer bytes.Buffer
	var keys []string
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for ix, k := range keys {
		buffer.WriteString(k + ": ")
		values := headers[k]
		for i, val := range values {
			if i == len(values) + 1 {
				buffer.WriteString(val)
			} else {
				buffer.WriteString(val + ", ")
			}
		}
		if ix < (len(keys) - 1) { 
			buffer.WriteString("\n")
		}
	}

	return string(buffer.Bytes())
}

type ResponseData struct {
	Input, Output, Field string
	Valid bool
}

type ProxyResponse struct {
	InUrl, InBody, Status, OutBody, OutHeaders, InHeaders string
	Valid bool  
}