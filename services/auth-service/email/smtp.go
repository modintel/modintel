package email

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"
)

type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	FromName string
	UseTLS   bool
}

func (c Config) IsConfigured() bool {
	return strings.TrimSpace(c.Host) != "" &&
		strings.TrimSpace(c.From) != "" &&
		c.Port > 0
}

func send(cfg Config, to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)

	fromHeader := cfg.From
	if strings.TrimSpace(cfg.FromName) != "" {
		fromHeader = fmt.Sprintf("%s <%s>", cfg.FromName, cfg.From)
	}

	msg := buildMessage(fromHeader, to, subject, body)

	var auth smtp.Auth
	if cfg.Username != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}

	if cfg.UseTLS {
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
		if err != nil {
			return fmt.Errorf("smtp tls dial: %w", err)
		}
		client, err := smtp.NewClient(conn, cfg.Host)
		if err != nil {
			return fmt.Errorf("smtp new client: %w", err)
		}
		defer client.Close()
		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
		return sendViaClient(client, cfg.From, to, msg)
	}

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer client.Close()

	if ok, _ := client.Extension("STARTTLS"); ok {
		tlsCfg := &tls.Config{ServerName: cfg.Host}
		if err := client.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}

	return sendViaClient(client, cfg.From, to, msg)
}

func sendViaClient(client *smtp.Client, from, to string, msg []byte) error {
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

func sanitizeEmailBody(s string) string {
	s = strings.ReplaceAll(s, "\r\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

func buildMessage(from, to, subject, body string) []byte {
	safeBody := sanitizeEmailBody(body)

	encBody := base64.StdEncoding.EncodeToString([]byte(safeBody))
	decBody, _ := base64.StdEncoding.DecodeString(encBody)
	cleanBody := string(decBody)

	var qpBuf bytes.Buffer
	qpWriter := quotedprintable.NewWriter(&qpBuf)
	_, _ = qpWriter.Write([]byte(cleanBody))
	_ = qpWriter.Close()

	var sb strings.Builder
	sb.WriteString("From: " + sanitizeSMTPHeader(from) + "\r\n")
	sb.WriteString("To: " + sanitizeSMTPHeader(to) + "\r\n")
	sb.WriteString("Subject: " + sanitizeSMTPHeader(subject) + "\r\n")
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	sb.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
	sb.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(qpBuf.String())
	return []byte(sb.String())
}

func sanitizeSMTPHeader(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > 998 {
		s = s[:998]
	}
	return s
}


const maxSMTPRetries = 3

func sendWithRetry(cfg Config, to, subject, body string) error {
	backoff := 500 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt <= maxSMTPRetries; attempt++ {
		if attempt > 0 {
			time.Sleep(backoff)
			backoff *= 2
		}
		if err := send(cfg, to, subject, body); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("smtp: failed after %d retries: %w", maxSMTPRetries, lastErr)
}


func SendInviteEmail(cfg Config, toEmail, invitedByName, role, acceptLink string) error {
	subject := "You've been invited to ModIntel"
	roleDisplay := role
	if len(role) > 0 {
		roleDisplay = strings.ToUpper(role[:1]) + strings.ToLower(role[1:])
	}
	body := fmt.Sprintf(`Hi,

%s has invited you to join ModIntel as %s.

Click the link below to accept your invitation and create your account:

  %s

This link expires in 24 hours.

If you did not expect this invitation, you can safely ignore this email.

— ModIntel Security Platform
`, invitedByName, roleDisplay, acceptLink)

	return sendWithRetry(cfg, toEmail, subject, body)
}

func SendResetEmail(cfg Config, toEmail, resetLink string) error {
	subject := "ModIntel — Password Reset Request"
	body := fmt.Sprintf(`Hi,

We received a request to reset the password for your ModIntel account.

Click the link below to set a new password:

  %s

This link expires in 1 hour. If you did not request a password reset, you can safely ignore this email — your password will not change.

— ModIntel Security Platform
`, resetLink)

	return sendWithRetry(cfg, toEmail, subject, body)
}

func SendTestEmail(cfg Config, toEmail string) error {
	subject := "ModIntel — SMTP Test"
	body := `This is a test email from ModIntel.

If you received this, your SMTP configuration is working correctly.

— ModIntel Security Platform
`
	return sendWithRetry(cfg, toEmail, subject, body)
}