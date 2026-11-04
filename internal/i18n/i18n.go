// Package i18n traduit l'interface de Gatewyn du français (langue de référence) vers l'anglais.
//
// Le français n'est jamais modifié : les gabarits et les messages du code restent écrits en
// français. Pour l'anglais, la page rendue est traduite après coup par un catalogue (en.go) dont
// les clés sont les textes français. Une clé peut contenir %s, %d ou %q pour la partie variable
// (nom d'hôte, nombre…), et peut être un simple morceau de phrase : les messages construits par
// morceaux (« nom » + « est publié. ») se traduisent morceau par morceau.
package i18n

import (
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

type entry struct{ fr, en string }

type rule struct {
	re          *regexp.Regexp
	lowerFirst  bool   // la clé commence par une minuscule : le texte peut commencer par une majuscule
	lit         string // plus long morceau fixe du français : filtre rapide avant l'expression régulière
	en          string // modèle anglais ; %s, %d, %q reçoivent les valeurs relevées dans le texte
	lead, trail bool   // la clé commence / finit par une lettre : vérifier la frontière de mot
	weight      int
}

var (
	rules   []rule
	cache   sync.Map // texte français → traduction
	cacheN  int
	cacheMu sync.Mutex
)

var verbRe = regexp.MustCompile(`%[sdqvw]`)

// entries réunit les textes de l'interface (en.go) et les messages du code Go (en_messages.go).
var entries = append(append([]entry{}, uiEntries...), messageEntries...)

var once sync.Once

func ready() { once.Do(func() { rules = compile(entries) }) }

// norm met un texte sous la forme des clés : espaces réduits, apostrophe droite.
func norm(s string) string {
	s = strings.ReplaceAll(s, "’", "'")
	return strings.Join(strings.Fields(s), " ")
}

func compile(list []entry) []rule {
	out := make([]rule, 0, len(list))
	for _, e := range list {
		fr := norm(e.fr)
		parts := verbRe.Split(fr, -1)
		verbs := verbRe.FindAllString(fr, -1)
		var b strings.Builder
		lit := ""
		for i, p := range parts {
			b.WriteString(regexp.QuoteMeta(p))
			if len(p) > len(lit) {
				lit = p
			}
			if i < len(verbs) {
				// Une valeur en fin de phrase peut contenir des points (adresse IP, nom de domaine) :
				// elle est gloutonne quand seule une ponctuation la suit.
				tail := ""
				if i+1 < len(parts) {
					tail = parts[i+1]
				}
				last := i == len(verbs)-1 && utf8.RuneCountInString(strings.TrimFunc(tail, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })) == 0 && utf8.RuneCountInString(tail) <= 2
				switch verbs[i] {
				case "%d":
					b.WriteString(`(\d+)`)
				case "%q":
					b.WriteString(`("[^"]*"|'[^']*')`)
				default:
					if last {
						b.WriteString(`(.+)`)
					} else {
						b.WriteString(`(.+?)`)
					}
				}
			}
		}
		first, _ := utf8.DecodeRuneInString(fr)
		last, _ := utf8.DecodeLastRuneInString(fr)
		pattern := b.String()
		// Une clé en minuscule vaut aussi pour sa version capitalisée (« Le mot de passe… » est le même
		// message en début de phrase) ; une clé qui commence par une majuscule est prise telle quelle.
		if unicode.IsLower(first) {
			pattern = "(?i)" + pattern
		}
		re := regexp.MustCompile(pattern)
		out = append(out, rule{
			re: re, lit: lit, en: e.en, lowerFirst: unicode.IsLower(first),
			lead: unicode.IsLetter(first) || unicode.IsDigit(first), trail: unicode.IsLetter(last) || unicode.IsDigit(last),
			weight: utf8.RuneCountInString(fr),
		})
	}
	// Les clés les plus longues d'abord : une phrase complète passe avant ses morceaux.
	sortRules(out)
	return out
}

func sortRules(r []rule) {
	for i := 1; i < len(r); i++ {
		for j := i; j > 0 && r[j].weight > r[j-1].weight; j-- {
			r[j], r[j-1] = r[j-1], r[j]
		}
	}
}

func isWord(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }

func boundaryOK(s string, start, end int, r rule) bool {
	if r.lead && start > 0 {
		if p, _ := utf8.DecodeLastRuneInString(s[:start]); isWord(p) {
			return false
		}
	}
	if r.trail && end < len(s) {
		if n, _ := utf8.DecodeRuneInString(s[end:]); isWord(n) {
			return false
		}
	}
	return true
}

// Text traduit un texte français en anglais. Un texte sans traduction est rendu tel quel.
func Text(s string) string {
	lead := s[:len(s)-len(strings.TrimLeftFunc(s, unicode.IsSpace))]
	rest := strings.TrimLeftFunc(s, unicode.IsSpace)
	core := strings.TrimRightFunc(rest, unicode.IsSpace)
	trail := rest[len(core):]
	if core == "" {
		return s
	}
	if v, ok := cache.Load(core); ok {
		return lead + v.(string) + trail
	}
	out := translateCore(norm(core))
	cacheMu.Lock()
	if cacheN > 20000 { // borne la mémoire : les textes variables (noms d'hôtes) ne se répètent pas
		cache.Range(func(k, _ any) bool { cache.Delete(k); return true })
		cacheN = 0
	}
	cacheN++
	cacheMu.Unlock()
	cache.Store(core, out)
	return lead + out + trail
}

const tokenMark = "\x00"

func translateCore(n string) string {
	ready()
	var toks []string
	out := n
	lowered := strings.ToLower(out)
	for _, r := range rules {
		if !strings.Contains(lowered, strings.ToLower(r.lit)) {
			continue
		}
		locs := r.re.FindAllStringSubmatchIndex(out, -1)
		if locs == nil {
			continue
		}
		var b strings.Builder
		last := 0
		for _, loc := range locs {
			start, end := loc[0], loc[1]
			if !boundaryOK(out, start, end, r) {
				continue
			}
			args := make([]string, 0, len(loc)/2-1)
			for i := 2; i+1 < len(loc); i += 2 {
				args = append(args, out[loc[i]:loc[i+1]])
			}
			b.WriteString(out[last:start])
			en := render(r.en, args)
			if r.lowerFirst {
				if f, _ := utf8.DecodeRuneInString(out[start:]); unicode.IsUpper(f) {
					en = upperFirst(en)
				}
			}
			toks = append(toks, en)
			b.WriteString(tokenMark + strconv.Itoa(len(toks)-1) + tokenMark)
			last = end
		}
		if last == 0 && b.Len() == 0 {
			continue
		}
		b.WriteString(out[last:])
		out = b.String()
		lowered = strings.ToLower(out)
	}
	for strings.Contains(out, tokenMark) {
		before := out
		for i := len(toks) - 1; i >= 0; i-- {
			out = strings.Replace(out, tokenMark+strconv.Itoa(i)+tokenMark, toks[i], 1)
		}
		if out == before {
			break
		}
	}
	return localize(out)
}

func upperFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	return string(unicode.ToUpper(r)) + s[n:]
}

// render remplit le modèle anglais avec les valeurs relevées ; une valeur qui est elle-même un
// message français (erreur imbriquée) est traduite à son tour.
func render(en string, args []string) string {
	i := 0
	return verbRe.ReplaceAllStringFunc(en, func(string) string {
		if i >= len(args) {
			return ""
		}
		a := args[i]
		i++
		if !strings.Contains(a, tokenMark) && !strings.HasPrefix(a, `"`) && !strings.HasPrefix(a, "'") {
			a = translateCore(a)
		}
		return a
	})
}

var (
	dateFull  = regexp.MustCompile(`\b(\d{2})/(\d{2})/(\d{4})\b`)
	dateShort = regexp.MustCompile(`\b(\d{2})/(\d{2}) (\d{2}:\d{2}(?::\d{2})?)\b`)
	months    = []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
)

// localize adapte les dates écrites à la française (jj/mm/aaaa, jj/mm hh:mm).
func localize(s string) string {
	s = dateFull.ReplaceAllString(s, "$3-$2-$1")
	return dateShort.ReplaceAllStringFunc(s, func(m string) string {
		g := dateShort.FindStringSubmatch(m)
		mon, _ := strconv.Atoi(g[2])
		day, _ := strconv.Atoi(g[1])
		if mon < 1 || mon > 12 {
			return m
		}
		return months[mon] + " " + strconv.Itoa(day) + " " + g[3]
	})
}

var (
	accented  = regexp.MustCompile(`[àâäçéèêëîïôöùûüÿœ]`)
	stopwords = regexp.MustCompile(`(?i)\b(le|la|les|des|du|un|une|et|ou|pour|vous|votre|vos|est|sont|avec|dans|sur|pas|cette|qui|que|aux|ne|nous|mais|aussi|chez|vers|depuis|sans|sous|leur|soit|ainsi|lorsque|donc|car)\b`)
)

// LooksFrench dit si un texte semble être du français : une lettre accentuée ou un mot-outil.
// Sert aux tests, pour repérer ce qui n'a pas été traduit.
func LooksFrench(s string) bool {
	s = strings.ReplaceAll(s, "Français", "")
	return accented.MatchString(strings.ToLower(s)) || stopwords.MatchString(s)
}
