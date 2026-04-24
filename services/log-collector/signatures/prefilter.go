package signatures

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

type SignaturePattern struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Severity    string   `json:"severity"`
	Patterns    []string `json:"patterns"`
	Description string   `json:"description"`
}

type Prefilter struct {
	patterns []SignaturePattern
	compiled map[string][]*regexp.Regexp
}

func Load(path string) (*Prefilter, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var patterns []SignaturePattern
	if err := json.Unmarshal(data, &patterns); err != nil {
		return nil, err
	}

	pf := &Prefilter{
		patterns: patterns,
		compiled: make(map[string][]*regexp.Regexp),
	}

	for _, p := range patterns {
		var regs []*regexp.Regexp
		for _, pat := range p.Patterns {
			if r, err := regexp.Compile(pat); err == nil {
				regs = append(regs, r)
			}
		}
		if len(regs) > 0 {
			pf.compiled[p.ID] = regs
		}
	}

	return pf, nil
}

func (pf *Prefilter) Evaluate(method, uri, body string, headers map[string]string) (bool, []string) {
	if pf == nil {
		return false, nil
	}

	text := method + " " + uri + " " + body
	for k, v := range headers {
		lowerKey := strings.ToLower(k)
		if lowerKey != "user-agent" && lowerKey != "cookie" {
			text += " " + v
		}
	}
	textLower := text

	matched := []string{}
	for _, p := range pf.patterns {
		regs, ok := pf.compiled[p.ID]
		if !ok {
			continue
		}
		for _, r := range regs {
			if r.MatchString(textLower) {
				matched = append(matched, p.ID)
				break
			}
		}
	}

	return len(matched) > 0, matched
}
