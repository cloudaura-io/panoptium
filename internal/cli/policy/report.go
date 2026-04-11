package policy

const (
	SeverityError   = "error"
	SeverityWarning = "warning"
)

const (
	StatusOK      = "ok"
	StatusError   = "error"
	StatusWarning = "warning"
	StatusSkipped = "skipped"
)

type Diagnostic struct {
	Severity string `json:"severity"          yaml:"severity"`
	Rule     string `json:"rule,omitempty"    yaml:"rule,omitempty"`
	Field    string `json:"field,omitempty"   yaml:"field,omitempty"`
	Message  string `json:"message"           yaml:"message"`
}

type ResultItem struct {
	Source      string       `json:"source"               yaml:"source"`
	DocIndex    int          `json:"docIndex"             yaml:"docIndex"`
	Line        int          `json:"line,omitempty"       yaml:"line,omitempty"`
	Kind        string       `json:"kind,omitempty"       yaml:"kind,omitempty"`
	Name        string       `json:"name,omitempty"       yaml:"name,omitempty"`
	Namespace   string       `json:"namespace,omitempty"  yaml:"namespace,omitempty"`
	Status      string       `json:"status"               yaml:"status"`
	Diagnostics []Diagnostic `json:"diagnostics,omitempty" yaml:"diagnostics,omitempty"`
}

func (r ResultItem) Location() string {
	if r.Line > 0 {
		return fmtLoc(r.Source, r.Line)
	}
	return r.Source
}

type Summary struct {
	Total    int `json:"total"    yaml:"total"`
	OK       int `json:"ok"       yaml:"ok"`
	Errors   int `json:"errors"   yaml:"errors"`
	Warnings int `json:"warnings" yaml:"warnings"`
	Skipped  int `json:"skipped"  yaml:"skipped"`
}

type Report struct {
	Results []ResultItem `json:"results" yaml:"results"`
	Summary Summary      `json:"summary" yaml:"summary"`
}

func (r *Report) recompute() {
	r.Summary = Summary{Total: len(r.Results)}
	for _, item := range r.Results {
		switch item.Status {
		case StatusOK:
			r.Summary.OK++
		case StatusError:
			r.Summary.Errors++
		case StatusWarning:
			r.Summary.Warnings++
		case StatusSkipped:
			r.Summary.Skipped++
		}
	}
}

func fmtLoc(source string, line int) string {
	buf := make([]byte, 0, len(source)+8)
	buf = append(buf, source...)
	buf = append(buf, ':')
	if line < 10 {
		buf = append(buf, byte('0'+line))
	} else {
		digits := make([]byte, 0, 8)
		for line > 0 {
			digits = append([]byte{byte('0' + line%10)}, digits...)
			line /= 10
		}
		buf = append(buf, digits...)
	}
	return string(buf)
}
