package superheader

import (
	"net/http"
)

// stripHeaders removes a predefined list of sensitive HTTP headers to help prevent
// information disclosure as part of the best practices outlined by OWASP. This ensures
// that headers which might leak unnecessary details about the server or environment
// are stripped from the response before being sent to the client.
//
// For more information, refer to OWASP's best practices for securing HTTP headers:
// https://owasp.org/www-project-secure-headers/index.html#div-bestpractices_prevent-information-disclosure-via-http-headers
//
// This method works in a case-insensitive manner, meaning it will remove headers like
// "X-Powered-By", "x-powered-by", or any case variation.
func stripHeaders(rw http.ResponseWriter) {
	// List of headers to strip
	headersToRemove := []string{
		"$wsep",
		"Host-Header",
		"K-Proxy-Request",
		"Liferay-Portal",
		"OracleCommerceCloud-Version",
		"Pega-Host",
		"Powered-By",
		"Product",
		"Server",
		"SourceMap",
		"X-AspNet-Version",
		"X-AspNetMvc-Version",
		"X-Atmosphere-error",
		"X-Atmosphere-first-request",
		"X-Atmosphere-tracking-id",
		"X-B3-ParentSpanId",
		"X-B3-Sampled",
		"X-B3-SpanId",
		"X-B3-TraceId",
		"X-BEServer",
		"X-Backside-Transport",
		"X-CF-Powered-By",
		"X-CMS",
		"X-CalculatedBETarget",
		"X-Cocoon-Version",
		"X-Content-Encoded-By",
		"X-DiagInfo",
		"X-Envoy-Attempt-Count",
		"X-Envoy-External-Address",
		"X-Envoy-Internal",
		"X-Envoy-Original-Dst-Host",
		"X-Envoy-Upstream-Service-Time",
		"X-FEServer",
		"X-Framework",
		"X-Generated-By",
		"X-Generator",
		"X-Jitsi-Release",
		"X-Joomla-Version",
		"X-Kubernetes-PF-FlowSchema-UI",
		"X-Kubernetes-PF-PriorityLevel-UID",
		"X-LiteSpeed-Cache",
		"X-LiteSpeed-Purge",
		"X-LiteSpeed-Tag",
		"X-LiteSpeed-Vary",
		"X-Litespeed-Cache-Control",
		"X-Mod-Pagespeed",
		"X-Nextjs-Cache",
		"X-Nextjs-Matched-Path",
		"X-Nextjs-Page",
		"X-Nextjs-Redirect",
		"X-OWA-Version",
		"X-Old-Content-Length",
		"X-OneAgent-JS-Injection",
		"X-Page-Speed",
		"X-Php-Version",
		"X-Powered-By",
		"X-Powered-By-Plesk",
		"X-Powered-CMS",
		"X-Redirect-By",
		"X-Server-Powered-By",
		"X-SourceFiles",
		"X-SourceMap",
		"X-Turbo-Charged-By",
		"X-Umbraco-Version",
		"X-Varnish-Backend",
		"X-Varnish-Server",
		"X-dtAgentId",
		"X-dtHealthCheck",
		"X-dtInjectedServlet",
		"X-ruxit-JS-Agent",
	}

	// Loop through the list of headers to remove and delete them from the request
	for _, header := range headersToRemove {
		rw.Header().Del(header)
	}

	// No need to send a response header. Just return after stripping headers.
}
