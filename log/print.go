package logger

func Debugf(format string, args ...any) {
	if logger.level >= DEBUG {
		logger.Printf("Debug: "+format, args)
	}
}

func Infof(format string, args ...any) {
	if logger.level >= INFO {
		logger.Printf("Info: "+format, args)
	}
}

func Warningf(format string, args ...any) {
	if logger.level >= WARNING {
		logger.Printf("Warn: "+format, args)
	}
}

func Errorf(format string, args ...any) {
	if logger.level >= ERROR {
		logger.Println("Error: "+format, args)
	}
}

func Fatalf(format string, args ...any) {
	if logger.level >= FATAL {
		logger.Fatalf(format, args...)
	}
}

func Panicf(format string, args ...any) {
	if logger.level >= PANIC {
		logger.Panicf(format, args...)
	}
}

func Debugln(args ...any) {
	if logger.level >= DEBUG {
		logger.Println(append([]any{"Debug:"}, args...)...)
	}
}

func Infoln(args ...any) {
	if logger.level >= INFO {
		logger.Println(append([]any{"Info:"}, args...)...)
	}
}

func Warningln(args ...any) {
	if logger.level >= WARNING {
		logger.Println(append([]any{"Warning:"}, args...)...)
	}
}

func Errorln(args ...any) {
	if logger.level >= ERROR {
		logger.Println(append([]any{"Error:"}, args...)...)
	}
}

func Fatalln(args ...any) {
	if logger.level >= FATAL {
		logger.Fatalln(args...)
	}
}

func Panicln(args ...any) {
	if logger.level >= PANIC {
		logger.Panicln(args...)
	}
}
