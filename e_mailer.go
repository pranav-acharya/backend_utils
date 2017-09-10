package backend_utils

import (
	"net/smtp"
	"text/template"
	"github.com/aloknerurkar/task-runner"
	"os"
	"fmt"
	"bytes"
	"time"
	tpl "html/template"
)

type EmailConf struct {
	Host     string
	Port     int
	UserName string
	Password string
	Auth     smtp.Auth
	Template *template.Template
}

type MailerDaemonType interface {
	SendEmail(to, subject, message string, args... interface{})
}

type MailerDaemon struct {
	conf *EmailConf
	runner *task_runner.TaskRunner
}

var emailScript = `From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}
MIME-version: 1.0
Content-Type: text/html; charset="UTF-8"
<html><body>{{.Message}}</body></html>`

func NewMailerDaemon(host, username, password string, port int) *MailerDaemon {

	daemon := new(MailerDaemon)
	daemon.conf = &EmailConf{
		Host: 	  host,
		Port: 	  port,
		UserName: username,
		Password: password,
		Auth:     smtp.PlainAuth("", username, password, host),
		Template: template.Must(template.New("emailTpl").Parse(emailScript)),
	}
	daemon.runner = task_runner.StartTaskRunner(2, os.Stdout)
	return daemon
}

func (s *MailerDaemon) SendEmail(to, subject, message string, args... interface{}) {
	task := NewEmailSendTask(taskParams{
		From: "no-reply@kuber.com",
		To: to,
		Subject: subject,
		Message: tpl.HTML(fmt.Sprintf(message, args...)),
	}, s)

	s.runner.EnqueueTask(task)
}

type taskParams struct {
	From    string
	To      string
	Subject string
	Message tpl.HTML
}

type emailTask struct {
	params taskParams
	sndr *MailerDaemon
	tries int
}

func NewEmailSendTask(parms taskParams, sender *MailerDaemon) *emailTask {
	return &emailTask{
		params: parms,
		sndr: sender,
		tries: 3,
	}
}

func (t *emailTask) Execute() {
	var emailMessage bytes.Buffer
	t.sndr.conf.Template.Execute(&emailMessage, &t.params)

	err := smtp.SendMail(fmt.Sprintf("%s:%d", t.sndr.conf.Host, t.sndr.conf.Port), t.sndr.conf.Auth,
		t.params.From, []string{t.params.To}, emailMessage.Bytes())

	if err != nil && t.tries > 0 {
		t.tries--
		time.Sleep(100 * time.Millisecond)
		t.Execute()
	}
}



