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

### Base64

Encode and decode in Base64.

### Hashing

Create hash values in either MD5 or SHA-1 format. 

## TODO List

- Expand JSON Validator
	- Add dynamic JSON viewer, for parsing, dynamic filtering, templating
	- Json Compare
- Merge Hashing pages
- Add automated tests
- Send feedback as email / store in DB
- Handle Time Zone input
