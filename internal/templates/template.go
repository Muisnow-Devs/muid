package templates

import (
	"embed"
	"fmt"
	"sync"
	"text/template"
)

//go:embed */*.html
var TemplatesFS embed.FS

type Loader struct {
	cache sync.Map
}

func NewLoader(fs embed.FS) *Loader {
	return &Loader{cache: sync.Map{}}
}

func (l *Loader) Load(locale, name string) (*template.Template, error) {
	key := locale + ":" + name

	// cache hit
	if v, ok := l.cache.Load(key); ok {
		return v.(*template.Template), nil
	}

	path := fmt.Sprintf("%s/%s.html", locale, name)

	tmpl, err := template.ParseFS(TemplatesFS, path)
	if err != nil {
		// fallback（重要）
		if locale != "en" {
			return l.Load("en", name)
		}
		return nil, err
	}

	l.cache.Store(key, tmpl)
	return tmpl, nil
}
