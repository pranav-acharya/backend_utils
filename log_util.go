package backend_utils

import (
	"github.com/goinggo/tracelog"
	"fmt"
)

type LogUtil struct {
	pkg_name string
	trace_level int32
	email_alerts []string
}

func InitLogger(pkgName string, traceLevel int32, use_stdout bool) *LogUtil {
	logger := new(LogUtil)
	logger.pkg_name = pkgName
	logger.trace_level = traceLevel
	if ! use_stdout {
		tracelog.StartFile(logger.trace_level, logger.pkg_name + "_log", 365)
	} else {
		tracelog.Start(logger.trace_level)
	}
	logger.Info("====== Starting %s. ======", pkgName)
	return logger
}

func (l *LogUtil) AddEmailAlert(emails []string) {
	copy(l.email_alerts, emails)
	tracelog.ConfigureEmail("smtp.gmail.com", 587, "username", "password", l.email_alerts)
}

func (l *LogUtil) FuncEntry(format string, args... interface{}) {
	tracelog.Startedfcd(3, l.pkg_name, MyCaller(), format, args...)
}

func (l *LogUtil) FuncExit(format string, args... interface{}) {
	tracelog.Completedfcd(3, l.pkg_name, MyCaller(), format, args...)
}

func (l *LogUtil) Info(format string, args... interface{}) {
	msg := fmt.Sprintf(format, args...)
	tracelog.Infocd(3, l.pkg_name, MyCaller(), msg)
}

func (l *LogUtil) Error(e error, format string, args... interface{}) error {
	tracelog.Errorfcd(3, e, l.pkg_name, MyCaller(), format, args...)
	return e
}

func (l *LogUtil) Panic(e error, format string, args... interface{}) error {
	if l.trace_level < tracelog.LevelInfo {
		panic(e)
	}
	tracelog.Alertcd(3, "Panic in " + l.pkg_name, l.pkg_name, MyCaller(), format, args...)
	tracelog.Errorfcd(3, e, l.pkg_name, MyCaller(), format, args...)
	return e
}