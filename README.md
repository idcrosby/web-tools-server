web-tools-server
================

## DESCRIPTION

Web app on top of web-tools library.
Back end: Go
Front end: HTML/Bootstrap/Javascript

## DETAILS

The following functions are availble:

### JSON

Json validation and formatting.

Json filtering, remove (or keep) only the selected elements from the JSON data.
Filter is passed in as comma delimited fields. Sub fields indicated with dot '.' separation.

### Time

Convert between Unix Epoch Time and Human readable time.
Current Unix Epoch time provided as real time clock.

### Encoding

Encode and decode in Base64 or URL encoding.

### Hashing

Create hash values in either MD5 or SHA-1 format. 

## TODO List

- Add Admin login.
- Ping/latency tool
- Expand JSON Validator
	- Add dynamic JSON viewer, for parsing, dynamic filtering, templating
	- Json Compare
- Add JSON Merge tool
- Add automated tests
- Send feedback as email / store in DB
- Handle Time Zone input
- Implement search
- Enhance Proxy
	- generate sig
	- delete saved response
	- option to add Content-Length header
	- save option (entire request and response, to file?)
	- size appropirately if no line breaks
	- save responses to file
	- authentication
	- filtering
	- store calls
	- split/make multiple calls
	- format body based on content-type header (raw/formatted option)
	- save state?
	- oauth integration
	- typeahead for headers?
