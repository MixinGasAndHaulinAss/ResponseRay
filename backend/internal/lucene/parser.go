package lucene

import (
	"fmt"
	"strings"
	"unicode"
)

// Node types for the AST

type Node interface {
	nodeType() string
}

type FieldNode struct {
	Field    string
	Value    string
	Wildcard bool // value ends with *
	Exists   bool // value is exactly *
}

func (n *FieldNode) nodeType() string { return "field" }

type NotNode struct {
	Child Node
}

func (n *NotNode) nodeType() string { return "not" }

type AndNode struct {
	Left  Node
	Right Node
}

func (n *AndNode) nodeType() string { return "and" }

type OrNode struct {
	Left  Node
	Right Node
}

func (n *OrNode) nodeType() string { return "or" }

// Token types

type tokenKind int

const (
	tokEOF tokenKind = iota
	tokWord
	tokQuoted
	tokColon
	tokLParen
	tokRParen
	tokMinus
	tokAND
	tokOR
	tokNOT
)

type token struct {
	kind tokenKind
	val  string
}

// Tokenizer

func tokenize(input string) []token {
	var tokens []token
	runes := []rune(input)
	i := 0

	for i < len(runes) {
		ch := runes[i]

		if unicode.IsSpace(ch) {
			i++
			continue
		}

		switch ch {
		case ':':
			tokens = append(tokens, token{tokColon, ":"})
			i++
		case '(':
			tokens = append(tokens, token{tokLParen, "("})
			i++
		case ')':
			tokens = append(tokens, token{tokRParen, ")"})
			i++
		case '-':
			tokens = append(tokens, token{tokMinus, "-"})
			i++
		case '"':
			i++
			start := i
			for i < len(runes) && runes[i] != '"' {
				i++
			}
			tokens = append(tokens, token{tokQuoted, string(runes[start:i])})
			if i < len(runes) {
				i++ // skip closing quote
			}
		default:
			start := i
			for i < len(runes) && !unicode.IsSpace(runes[i]) && runes[i] != ':' && runes[i] != '(' && runes[i] != ')' && runes[i] != '"' {
				i++
			}
			word := string(runes[start:i])
			upper := strings.ToUpper(word)
			switch upper {
			case "AND":
				tokens = append(tokens, token{tokAND, word})
			case "OR":
				tokens = append(tokens, token{tokOR, word})
			case "NOT":
				tokens = append(tokens, token{tokNOT, word})
			default:
				tokens = append(tokens, token{tokWord, word})
			}
		}
	}

	tokens = append(tokens, token{tokEOF, ""})
	return tokens
}

// Parser

type parser struct {
	tokens []token
	pos    int
}

func Parse(input string) (Node, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil, nil
	}
	p := &parser{tokens: tokenize(input)}
	node, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (p *parser) peek() token {
	if p.pos >= len(p.tokens) {
		return token{tokEOF, ""}
	}
	return p.tokens[p.pos]
}

func (p *parser) next() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) parseOr() (Node, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOR {
		p.next()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &OrNode{Left: left, Right: right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Node, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		pk := p.peek()
		if pk.kind == tokAND {
			p.next()
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = &AndNode{Left: left, Right: right}
		} else if pk.kind == tokWord || pk.kind == tokQuoted || pk.kind == tokLParen || pk.kind == tokMinus || pk.kind == tokNOT {
			// implicit AND
			right, err := p.parseUnary()
			if err != nil {
				return nil, err
			}
			left = &AndNode{Left: left, Right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *parser) parseUnary() (Node, error) {
	if p.peek().kind == tokMinus {
		p.next()
		child, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child}, nil
	}
	if p.peek().kind == tokNOT {
		p.next()
		child, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &NotNode{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Node, error) {
	t := p.peek()

	if t.kind == tokLParen {
		p.next()
		node, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind == tokRParen {
			p.next()
		}
		return node, nil
	}

	if t.kind == tokQuoted {
		p.next()
		return &FieldNode{Field: "message", Value: t.val}, nil
	}

	if t.kind == tokWord {
		p.next()
		// Check if next token is colon (field:value pattern)
		if p.peek().kind == tokColon {
			p.next() // consume colon
			field := t.val
			vt := p.peek()
			switch vt.kind {
			case tokQuoted:
				p.next()
				return &FieldNode{Field: field, Value: vt.val}, nil
			case tokWord:
				p.next()
				if vt.val == "*" {
					return &FieldNode{Field: field, Exists: true}, nil
				}
				wc := strings.HasSuffix(vt.val, "*")
				val := vt.val
				if wc {
					val = strings.TrimSuffix(val, "*")
				}
				return &FieldNode{Field: field, Value: val, Wildcard: wc}, nil
			default:
				return &FieldNode{Field: field, Exists: true}, nil
			}
		}
		// Bare word — search in message
		return &FieldNode{Field: "message", Value: t.val, Wildcard: true}, nil
	}

	if t.kind == tokEOF {
		return nil, fmt.Errorf("unexpected end of query")
	}
	return nil, fmt.Errorf("unexpected token: %q", t.val)
}
