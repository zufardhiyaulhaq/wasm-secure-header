package main

import (
	"strings"

	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm"
	"github.com/tetratelabs/proxy-wasm-go-sdk/proxywasm/types"
)

func main() {
	proxywasm.SetNewHttpContext(newHttpContext)
}

type httpHeaders struct {
	proxywasm.DefaultHttpContext
	contextID uint32
}

func newHttpContext(rootContextID, contextID uint32) proxywasm.HttpContext {
	return &httpHeaders{contextID: contextID}
}

func (ctx *httpHeaders) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	return types.ActionContinue
}

func headerExist(keyword string, headers [][2]string) bool {
	isExist := false

	for _, header := range headers {
		if header[0] == keyword {
			isExist = true
		}
	}

	return isExist
}

func frameAncestorsExist(value string) bool {
	return strings.Contains(value, "frame-ancestors")
}

func (ctx *httpHeaders) OnHttpResponseHeaders(numHeaders int, endOfStream bool) types.Action {
	hs, err := proxywasm.GetHttpResponseHeaders()

	if err != nil {
		proxywasm.LogCriticalf("failed to get response headers: %v", err)
	}

	if !headerExist("X-Frame-Options", hs) {
		proxywasm.AddHttpResponseHeader("X-Frame-Options", "deny")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: X-Frame-Options")
		}
	}

	if !headerExist("X-XSS-Protection", hs) {
		proxywasm.AddHttpResponseHeader("X-XSS-Protection", "1; mode=block")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: X-XSS-Protection")
		}
	}

	if !headerExist("X-Content-Type-Options", hs) {
		proxywasm.AddHttpResponseHeader("X-Content-Type-Options", "nosniff")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: X-Content-Type-Options")
		}
	}

	if !headerExist("Referrer-Policy", hs) {
		proxywasm.AddHttpResponseHeader("Referrer-Policy", "no-referrer")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: Referrer-Policy")
		}
	}

	if !headerExist("X-Download-Options", hs) {
		proxywasm.AddHttpResponseHeader("X-Download-Options", "noopen")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: X-Download-Options")
		}
	}

	if !headerExist("X-DNS-Prefetch-Control", hs) {
		proxywasm.AddHttpResponseHeader("X-DNS-Prefetch-Control", "off")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: X-DNS-Prefetch-Control")
		}
	}

	if !headerExist("Strict-Transport-Security", hs) {
		proxywasm.AddHttpResponseHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: Strict-Transport-Security")
		}
	}

	if !headerExist("Content-Security-Policy", hs) {
		proxywasm.AddHttpResponseHeader("Content-Security-Policy", "frame-ancestors none;")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: Content-Security-Policy")
		}
	} else {
		value, err := proxywasm.GetHttpRequestHeader("Content-Security-Policy")
		if err != nil {
			proxywasm.LogCriticalf("failed to get response headers: %v", err)
		}

		if !frameAncestorsExist(value) {
			value = value + ";frame-ancestors none;"
			proxywasm.SetHttpResponseHeader("Content-Security-Policy", value)
			if err != nil {
				proxywasm.LogCriticalf("failed to set response headers: %v", err)
			} else {
				proxywasm.LogInfof("success set response headers: Content-Security-Policy")
			}
		}
	}

	if !headerExist("Permissions-Policy", hs) {
		proxywasm.AddHttpResponseHeader("Permissions-Policy", "camera 'none';microphone 'none';geolocation 'none';encrypted-media 'none';payment 'none';speaker 'none';usb 'none';")
		if err != nil {
			proxywasm.LogCriticalf("failed to add response headers: %v", err)
		} else {
			proxywasm.LogInfof("success add response headers: Permissions-Policy")
		}
	}

	if headerExist("X-Powered-By", hs) {
		proxywasm.RemoveHttpResponseHeader("X-Powered-By")
		if err != nil {
			proxywasm.LogCriticalf("failed to remove response headers: %v", err)
		} else {
			proxywasm.LogInfof("success remove response headers: X-Powered-By")
		}
	}
	return types.ActionContinue
}

func (ctx *httpHeaders) OnHttpStreamDone() {
	proxywasm.LogInfof("%d finished", ctx.contextID)
}
