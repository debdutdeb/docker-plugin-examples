package main

import (
	"encoding/base64"
	"encoding/json"
	"regexp"

	"github.com/docker/go-plugins-helpers/authorization"
	"github.com/sirupsen/logrus"
)

type Plugin struct {
	// Will use a Unix socket
	name string
}

func (p *Plugin) AuthZReq(request authorization.Request) authorization.Response {
	response := authorization.Response{
		Allow: true,
		Msg:   "Permission granted",
	}
	if matched, err := regexp.MatchString(`.+/exec$`, request.RequestURI); nil != err {
		logrus.Error("URI check failed.")
	} else {
		if matched {
			if data, err := base64.RawStdEncoding.DecodeString(base64.RawStdEncoding.EncodeToString(request.RequestBody)); nil != err {
				logrus.Error("Request body decoding failed. Error: " + err.Error())
			} else {
				var requestBody map[string]interface{}
				if err = json.Unmarshal(data, &requestBody); nil != err {
					logrus.Error("Loading json request body failed.")
				}
				switch requestBody["User"].(string) {
				case "":
					fallthrough
				case "0":
					fallthrough
				case "root":
					response.Allow = false
					response.Msg = "Permission denied"
					response.Err = "/exec endpoint is currently blocked"
				}
			}
		}
	}
	return response
}

func (p *Plugin) AuthZRes(request authorization.Request) authorization.Response {
	return authorization.Response{
		Allow: true,
	}
}

func main() {
	plugin := &Plugin{name: "authz"}
	handler := authorization.NewHandler(plugin)
	if err := handler.ServeUnix(plugin.name, 0); nil != err {
		logrus.Fatal(err)
	}
}
