package templates

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"text/template"
	textTemplate "text/template"
)

const fallbackLocale = "en"

//go:embed layouts/*.html pages/*/content.html
var HTMLTemplatesFS embed.FS

//go:embed layouts/*.txt pages/*/content.txt
var TextTemplatesFS embed.FS

//go:embed locales/*/*.json
var LocaleTemplateFS embed.FS

type RenderedMail struct {
	HTML    string
	Text    string
	Subject string
}

type compiledTemplate struct {
	html    *template.Template
	text    *template.Template
	subject string
}

type TemplateLoader struct {
	htmlFS   embed.FS
	textFS   embed.FS
	localeFS embed.FS

	templateCache sync.Map
	messageCache  sync.Map
}

func NewTemplateLoader(htmlFS embed.FS, textFS embed.FS, localeFS embed.FS) *TemplateLoader {
	return &TemplateLoader{
		htmlFS:   htmlFS,
		textFS:   textFS,
		localeFS: localeFS,
	}
}

func translator(messages map[string]string) func(string, ...any) string {
	return func(key string, args ...any) string {
		msg, ok := messages[key]
		if !ok {
			return key
		}

		if len(args) == 0 {
			return msg
		}

		return fmt.Sprintf(msg, args...)
	}
}

func (l *TemplateLoader) loadMessages(
	locale string,
	page string,
) (map[string]string, error) {
	key := locale + ":" + page

	if v, ok := l.messageCache.Load(key); ok {
		return v.(map[string]string), nil
	}

	messages := make(map[string]string)

	// Load fallback locale first
	if locale != fallbackLocale {
		fallbackMessages, err := l.loadMessages(fallbackLocale, page)
		if err != nil {
			return nil, err
		}

		maps.Copy(messages, fallbackMessages)
	}

	path := filepath.ToSlash(
		fmt.Sprintf("locales/%s/%s.json", locale, page),
	)

	data, err := l.localeFS.ReadFile(path)
	if err != nil {
		if locale == fallbackLocale {
			return nil, err
		}

		// Fallback locale already loaded
		l.messageCache.Store(key, messages)

		return messages, nil
	}

	var localized map[string]string

	err = json.Unmarshal(data, &localized)
	if err != nil {
		return nil, err
	}

	maps.Copy(messages, localized)

	l.messageCache.Store(key, messages)

	return messages, nil
}

func (l *TemplateLoader) loadTemplates(
	page string,
	messages map[string]string,
) (*compiledTemplate, error) {
	cacheKey := page

	if v, ok := l.templateCache.Load(cacheKey); ok {
		return v.(*compiledTemplate), nil
	}

	tFunc := translator(messages)
	htmlTmpl, err := template.New("base").
		Funcs(template.FuncMap{
			"t": tFunc,
		}).
		ParseFS(
			l.htmlFS,
			"layouts/*.html",
			fmt.Sprintf("pages/%s/content.html", page),
		)
	if err != nil {
		return nil, err
	}

	textTmpl, err := textTemplate.New("base").
		Funcs(textTemplate.FuncMap{
			"t": tFunc,
		}).
		ParseFS(
			l.textFS,
			"layouts/*.txt",
			fmt.Sprintf("pages/%s/content.txt", page),
		)
	if err != nil {
		return nil, err
	}

	compiled := &compiledTemplate{
		html:    htmlTmpl,
		text:    textTmpl,
		subject: tFunc("subject"),
	}

	l.templateCache.Store(cacheKey, compiled)

	return compiled, nil
}

func executeHTMLTemplate(
	tmpl *template.Template,
	data any,
) (string, error) {
	var buf bytes.Buffer

	err := tmpl.ExecuteTemplate(&buf, "base", data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func executeTextTemplate(
	tmpl *textTemplate.Template,
	name string,
	data any,
) (string, error) {
	var buf bytes.Buffer

	err := tmpl.ExecuteTemplate(&buf, name, data)
	if err != nil {
		return "", err
	}

	return buf.String(), nil
}

func (l *TemplateLoader) Render(
	locale string,
	page string,
	data any,
) (*RenderedMail, error) {
	messages, err := l.loadMessages(locale, page)
	if err != nil {
		return nil, err
	}

	tmpl, err := l.loadTemplates(page, messages)
	if err != nil {
		return nil, err
	}

	htmlBody, err := executeHTMLTemplate(tmpl.html, data)
	if err != nil {
		return nil, err
	}

	textBody, err := executeTextTemplate(
		tmpl.text,
		"base",
		data,
	)
	if err != nil {
		return nil, err
	}

	return &RenderedMail{
		HTML:    htmlBody,
		Text:    textBody,
		Subject: tmpl.subject,
	}, nil
}
