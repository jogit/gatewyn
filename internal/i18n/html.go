package i18n

import (
	"bytes"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// Attributs dont la valeur est lue par la personne : à traduire comme le texte.
var textAttrs = map[string]bool{"title": true, "placeholder": true, "aria-label": true, "alt": true, "hx-confirm": true, "data-l": true}

// skipTags : contenus qui ne sont pas du texte à traduire (aperçu de configuration, saisies).
var skipTags = map[atom.Atom]bool{atom.Script: true, atom.Style: true, atom.Pre: true, atom.Textarea: true}

// HTML traduit une page ou un fragment HTML. Le texte et les attributs lisibles sont traduits ;
// la structure est conservée.
func HTML(body []byte) []byte {
	trimmed := strings.TrimSpace(string(body))
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") {
		doc, err := html.Parse(bytes.NewReader(body))
		if err != nil {
			return body
		}
		walk(doc)
		var buf bytes.Buffer
		if html.Render(&buf, doc) != nil {
			return body
		}
		return buf.Bytes()
	}
	nodes, err := html.ParseFragment(strings.NewReader(trimmed), contextFor(lower))
	if err != nil {
		return body
	}
	var buf bytes.Buffer
	for _, n := range nodes {
		walk(n)
		if html.Render(&buf, n) != nil {
			return body
		}
	}
	return buf.Bytes()
}

// contextFor choisit l'élément parent d'un fragment : un <tr> ou un <td> seul est supprimé par
// l'analyseur s'il n'a pas son tableau autour.
func contextFor(lower string) *html.Node {
	ctx := atom.Body
	switch {
	case strings.HasPrefix(lower, "<tr"):
		ctx = atom.Tbody
	case strings.HasPrefix(lower, "<td"), strings.HasPrefix(lower, "<th"):
		ctx = atom.Tr
	case strings.HasPrefix(lower, "<option"):
		ctx = atom.Select
	}
	return &html.Node{Type: html.ElementNode, DataAtom: ctx, Data: ctx.String()}
}

func walk(n *html.Node) {
	switch n.Type {
	case html.TextNode:
		if p := n.Parent; p == nil || !skipTags[p.DataAtom] {
			n.Data = Text(n.Data)
		}
		return
	case html.ElementNode:
		if skipTags[n.DataAtom] {
			return
		}
		for i, a := range n.Attr {
			switch {
			case textAttrs[a.Key]:
				n.Attr[i].Val = Text(a.Val)
			case a.Key == "lang" && n.DataAtom == atom.Html:
				n.Attr[i].Val = "en"
			case a.Key == "value" && n.DataAtom == atom.Input && isButton(n):
				n.Attr[i].Val = Text(a.Val)
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		walk(c)
	}
}

func isButton(n *html.Node) bool {
	for _, a := range n.Attr {
		if a.Key == "type" && (a.Val == "submit" || a.Val == "button") {
			return true
		}
	}
	return false
}
