package templates

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"sync"
	"text/template"
)

//go:embed layouts/*.html pages/*.html locales/*/*.json
var TemplatesFS embed.FS

type TemplateLoader struct {
	fs    embed.FS
	cache sync.Map
}

func NewTemplateLoader(fs embed.FS) *TemplateLoader {
	return &TemplateLoader{
		fs: fs,
	}
}

func (l *TemplateLoader) load(
	page string,
) (*template.Template, error) {
	key := page
	if v, ok := l.cache.Load(key); ok {
		return v.(*template.Template), nil
	}

	tmpl, err := template.New("").
		Funcs(template.FuncMap{
			"t": func(key string, args ...any) string {
				return key
			},
		}).
		ParseFS(
			l.fs,
			"layouts/*.html",
			fmt.Sprintf("pages/%s.html", page),
		)
	if err != nil {
		return nil, err
	}

	l.cache.Store(key, tmpl)

	return tmpl, nil
}

func (l *TemplateLoader) loadMessage(
	locale string,
	page string,
) (map[string]string, error) {

	messages := make(map[string]string)

	files := []string{
		fmt.Sprintf("locales/%s/%s.json", locale, page),
	}

	for _, file := range files {
		data, err := l.fs.ReadFile(file)
		if err != nil {
			if locale != "en" {
				return l.loadMessage("en", page)
			}

			return nil, err
		}

		var msg map[string]string

		err = json.Unmarshal(data, &msg)
		if err != nil {
			return nil, err
		}

		maps.Copy(messages, msg)
	}

	return messages, nil
}

func (l *TemplateLoader) Render(
	locale string,
	page string,
	data any,
) (string, error) {
	messages, err := l.loadMessage(locale, page)
	if err != nil {
		return "", err
	}

	baseTmpl, err := l.load(page)
	if err != nil {
		return "", err
	}

	tmpl, err := baseTmpl.Clone()
	if err != nil {
		return "", err
	}

	tmpl = tmpl.Funcs(template.FuncMap{
		"t": func(key string, args ...any) string {
			msg, ok := messages[key]
			if !ok {
				return key
			}

			if len(args) > 0 {
				return fmt.Sprintf(msg, args...)
			}

			return msg
		},
	})

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "base", data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}
