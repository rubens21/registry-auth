package registry

type logger struct {
}

func (l logger) Debugf(template string, args ...interface{}) {
	// muted
}

func (l logger) Infof(template string, args ...interface{}) {
	// muted
}

func (l logger) Warnf(template string, args ...interface{}) {
	// muted
}

func (l logger) Errorf(template string, args ...interface{}) {
	// muted
}
