// Package plugin provides smart template filtering for the Ouroboros scanner.
package plugin

import (
	"strings"

	"github.com/borntobeyours/ouroboros/internal/red/probers"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// FilterByTechnology returns the subset of probers relevant to the detected
// tech stack.  Rules:
//   - Templates with no tags or the "generic" tag always run.
//   - Tech-specific templates only run if a matching technology was detected.
//   - If techs is empty (recon disabled), only generic templates run.
func FilterByTechnology(ps []*PluginProber, techs []types.TechFingerprint) []*PluginProber {
	if len(techs) == 0 {
		return filterGenericOnly(ps)
	}

	techSet := buildTechSet(techs)

	var out []*PluginProber
	for _, p := range ps {
		if shouldRun(p, techSet) {
			out = append(out, p)
		}
	}
	return out
}

// FilterByTags returns probers whose effective tags overlap with the supplied
// tag list.  Generic templates (no tags / "generic") are always included.
func FilterByTags(ps []*PluginProber, wantTags []string) []*PluginProber {
	want := make(map[string]bool, len(wantTags))
	for _, t := range wantTags {
		want[strings.ToLower(t)] = true
	}

	var out []*PluginProber
	for _, p := range ps {
		tags := p.Tags()
		if len(tags) == 0 || containsTag(tags, "generic") {
			out = append(out, p)
			continue
		}
		for _, tag := range tags {
			if want[strings.ToLower(tag)] {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// ToProbers converts a slice of *PluginProber to the probers.Prober interface.
func ToProbers(ps []*PluginProber) []probers.Prober {
	out := make([]probers.Prober, len(ps))
	for i, p := range ps {
		out[i] = p
	}
	return out
}

// ──────────────────────────────────────────────
// helpers
// ──────────────────────────────────────────────

func filterGenericOnly(ps []*PluginProber) []*PluginProber {
	var out []*PluginProber
	for _, p := range ps {
		tags := p.Tags()
		if len(tags) == 0 || containsTag(tags, "generic") {
			out = append(out, p)
		}
	}
	return out
}

func shouldRun(p *PluginProber, techSet map[string]bool) bool {
	tags := p.Tags()
	if len(tags) == 0 || containsTag(tags, "generic") {
		return true
	}
	for _, tag := range tags {
		if techSet[strings.ToLower(tag)] {
			return true
		}
	}
	return false
}

// buildTechSet converts detected technologies into a normalised set of tags.
// It also adds implied tags (e.g. "express" implies "nodejs").
func buildTechSet(techs []types.TechFingerprint) map[string]bool {
	set := make(map[string]bool, len(techs)*2)
	for _, t := range techs {
		name := strings.ToLower(t.Name)
		set[name] = true

		// Expand common aliases so templates with implied tags match too.
		switch name {
		case "express", "express.js":
			set["express"] = true
			set["nodejs"] = true
		case "node.js", "node":
			set["nodejs"] = true
		case "react", "react.js":
			set["react"] = true
			set["javascript"] = true
		case "angular":
			set["angular"] = true
			set["javascript"] = true
		case "vue", "vue.js":
			set["vue"] = true
			set["javascript"] = true
		case "next.js", "nextjs":
			set["nodejs"] = true
			set["react"] = true
			set["javascript"] = true
		case "nuxt.js", "nuxtjs":
			set["nodejs"] = true
			set["vue"] = true
			set["javascript"] = true
		case "django":
			set["django"] = true
			set["python"] = true
		case "flask":
			set["flask"] = true
			set["python"] = true
		case "laravel":
			set["laravel"] = true
			set["php"] = true
		case "wordpress":
			set["wordpress"] = true
			set["php"] = true
		case "joomla":
			set["joomla"] = true
			set["php"] = true
		case "drupal":
			set["drupal"] = true
			set["php"] = true
		case "spring", "spring boot", "spring framework":
			set["spring"] = true
			set["java"] = true
		case "apache tomcat", "tomcat":
			set["tomcat"] = true
			set["java"] = true
		case "asp.net", "asp.net mvc", "asp.net core":
			set["aspnet"] = true
			set["dotnet"] = true
		case "ruby on rails", "rails":
			set["rails"] = true
			set["ruby"] = true
		case "grafana":
			set["grafana"] = true
		case "jenkins":
			set["jenkins"] = true
			set["java"] = true
		case "gitlab":
			set["gitlab"] = true
		case "elasticsearch":
			set["elasticsearch"] = true
		case "kibana":
			set["elasticsearch"] = true
			set["kibana"] = true
		case "nginx":
			set["nginx"] = true
		case "apache", "apache httpd":
			set["apache"] = true
		case "iis", "microsoft iis":
			set["iis"] = true
		case "php":
			set["php"] = true
		case "java":
			set["java"] = true
		case "python":
			set["python"] = true
		case "mysql":
			set["mysql"] = true
		case "postgresql", "postgres":
			set["postgres"] = true
		case "mongodb":
			set["mongodb"] = true
		case "redis":
			set["redis"] = true
		case "docker":
			set["docker"] = true
		case "kubernetes":
			set["kubernetes"] = true
		case "cloudflare":
			set["generic"] = true // WAF presence doesn't imply specific tech
		}
	}
	return set
}

func containsTag(tags []string, tag string) bool {
	for _, t := range tags {
		if strings.ToLower(t) == tag {
			return true
		}
	}
	return false
}
