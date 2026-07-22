package policy

import (
	"fmt"
	"regexp"
	"strings"
)

type globTokenKind uint8

const (
	globLiteral globTokenKind = iota
	globStar
	globTreeStar
	globQuestion
	globClass
)

type globClassPart struct {
	first rune
	last  rune
}

type globToken struct {
	kind    globTokenKind
	literal rune
	negated bool
	parts   []globClassPart
}

// parseGlob is the single canonical parser used by both regexp generation and
// the Windows ordinal matcher. An unmatched '[' is a literal, matching the
// historical GlobToRegexp contract; a syntactically closed but invalid class
// fails validation so callers retain their fail-closed allow/deny behavior.
func parseGlob(glob string) ([]globToken, error) {
	pattern := []rune(globPathKey(glob))
	tokens := make([]globToken, 0, len(pattern))
	for i := 0; i < len(pattern); {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				tokens = append(tokens, globToken{kind: globTreeStar})
				i += 2
			} else {
				tokens = append(tokens, globToken{kind: globStar})
				i++
			}
		case '?':
			tokens = append(tokens, globToken{kind: globQuestion})
			i++
		case '[':
			token, next, closed, err := parseGlobClass(pattern, i)
			if err != nil {
				return nil, err
			}
			if closed {
				tokens = append(tokens, token)
				i = next
			} else {
				tokens = append(tokens, globToken{kind: globLiteral, literal: pattern[i]})
				i++
			}
		default:
			tokens = append(tokens, globToken{kind: globLiteral, literal: pattern[i]})
			i++
		}
	}
	return tokens, nil
}

func parseGlobClass(pattern []rune, start int) (globToken, int, bool, error) {
	i := start + 1
	negated := false
	if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
		negated = true
		i++
	}
	bodyStart := i
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	for i < len(pattern) && pattern[i] != ']' {
		i++
	}
	if i == len(pattern) {
		return globToken{}, 0, false, nil
	}
	body := pattern[bodyStart:i]
	parts := make([]globClassPart, 0, len(body))
	for j := 0; j < len(body); {
		if j+2 < len(body) && body[j+1] == '-' {
			if body[j] > body[j+2] {
				return globToken{}, 0, true, fmt.Errorf("reversed glob class range %q-%q", body[j], body[j+2])
			}
			parts = append(parts, globClassPart{first: body[j], last: body[j+2]})
			j += 3
		} else {
			parts = append(parts, globClassPart{first: body[j], last: body[j]})
			j++
		}
	}
	return globToken{kind: globClass, negated: negated, parts: parts}, i + 1, true, nil
}

func globRegexpSource(tokens []globToken) string {
	var b strings.Builder
	b.WriteByte('^')
	separator := regexp.QuoteMeta(pathKeySeparator)
	for _, token := range tokens {
		switch token.kind {
		case globLiteral:
			b.WriteString(regexp.QuoteMeta(string(token.literal)))
		case globStar:
			b.WriteString("[^" + separator + "]*")
		case globTreeStar:
			b.WriteString(".*")
		case globQuestion:
			b.WriteString("[^" + separator + "]")
		case globClass:
			b.WriteByte('[')
			if token.negated {
				b.WriteByte('^')
			}
			for _, part := range token.parts {
				b.WriteString(regexp.QuoteMeta(string(part.first)))
				if part.first != part.last {
					b.WriteByte('-')
					b.WriteString(regexp.QuoteMeta(string(part.last)))
				}
			}
			b.WriteByte(']')
		}
	}
	b.WriteByte('$')
	return b.String()
}
