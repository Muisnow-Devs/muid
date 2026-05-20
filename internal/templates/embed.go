package templates

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"strings"
	"sync"
	"text/template"
	textTemplate "text/template"

	"golang.org/x/sync/errgroup"
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
	html *template.Template
	text *textTemplate.Template
}

type TemplateLoader struct {
	htmlFS   embed.FS
	textFS   embed.FS
	localeFS embed.FS

	templateCache sync.Map
	messageCache  sync.Map
}

// NewTemplateLoader returns a [MailRenderer] backed by the given embedded filesystems.
func NewTemplateLoader(htmlFS embed.FS, textFS embed.FS, localeFS embed.FS) MailRenderer {
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
	locale string,
	page string,
	messages map[string]string,
) (*compiledTemplate, error) {
	cacheKey := locale + ":" + page

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
		html: htmlTmpl,
		text: textTmpl,
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

func (l *TemplateLoader) renderSubject(messages map[string]string, data any) (string, error) {
	raw, ok := messages["subject"]
	if !ok || strings.TrimSpace(raw) == "" {
		return "", ErrMissingSubjectInLocaleBundle
	}
	tmpl, err := textTemplate.New("subject").Parse(raw)
	if err != nil {
		return "", errors.Join(ErrTemplateSubjectParseFailed, err)
	}
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return "", errors.Join(ErrTemplateSubjectExecFailed, err)
	}
	return strings.TrimSpace(buf.String()), nil
}

func (l *TemplateLoader) Render(
	ctx context.Context,
	locale string,
	page string,
	data any,
) (*RenderedMail, error) {
	err := validateTemplateSegment(locale, "locale")
	if err != nil {
		return nil, err
	}

	err = validateTemplateSegment(page, "page")
	if err != nil {
		return nil, err
	}

	messages, err := l.loadMessages(locale, page)
	if err != nil {
		return nil, err
	}

	tmpl, err := l.loadTemplates(locale, page, messages)
	if err != nil {
		return nil, err
	}

	var (
		htmlBody string
		textBody string
		subject  string
	)

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		var err error
		htmlBody, err = executeHTMLTemplate(tmpl.html, data)
		return err
	})

	g.Go(func() error {
		var err error
		textBody, err = executeTextTemplate(
			tmpl.text,
			"base",
			data,
		)
		return err
	})

	g.Go(func() error {
		var err error
		subject, err = l.renderSubject(messages, data)
		return err
	})

	err = g.Wait()
	if err != nil {
		return nil, err
	}

	return &RenderedMail{
		HTML:    htmlBody,
		Text:    textBody,
		Subject: subject,
	}, nil
}
