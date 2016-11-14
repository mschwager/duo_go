package main

import (
	"fmt"
	"html/template"
	"net/http"

	// The parent directory is the duo_go package
	".."
)

const IKEY = ""
const SKEY = ""
const AKEY = ""
const HOST = ""
const RESPONSE_URL = "/response"

const HTML_TEMPLATE = `
<html>
	<head>
		<style>
			#duo_iframe {
				width: 100%;
				min-width: 304px;
				max-width: 620px;
				height: 330px;
				border: none;
			}
		</style>
	</head>
	<body>
		<form method="post" id="duo_form"></form>
		<iframe id="duo_iframe"
				data-host="{{ .Host }}"
				data-sig-request="{{ .SigRequest }}"
				data-post-action="{{ .PostAction }}">
		</iframe>
		<script src="https://api.duosecurity.com/frame/hosted/Duo-Web-v2.min.js"></script>
	</body>
</html>
`

var DUO_CONFIGURATION = &duo_go.Web{
	Ikey: IKEY,
	Skey: SKEY,
	Akey: AKEY,
}

func handler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	sig_request, err := duo_go.SignRequest(DUO_CONFIGURATION, username)
	if err != nil {
		fmt.Println(err)
	}

	page := struct {
		Host       string
		SigRequest string
		PostAction string
	}{
		Host:       HOST,
		SigRequest: sig_request,
		PostAction: RESPONSE_URL,
	}

	p, err := template.New("example").Parse(HTML_TEMPLATE)
	if err != nil {
		fmt.Println(err)
	}

	p.ExecuteTemplate(w, "example", page)
}

func response(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	sig_response := r.FormValue("sig_response")

	username, err := duo_go.VerifyResponse(DUO_CONFIGURATION, sig_response)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Fprintf(w, "Successfully authenticated as: "+username)
}

func main() {
	fmt.Println("Listening on: http://localhost:8080/?username=example")
	http.HandleFunc("/", handler)
	http.HandleFunc(RESPONSE_URL, response)
	http.ListenAndServe(":8080", nil)
}
