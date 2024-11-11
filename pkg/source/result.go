package source

type Result struct {
	Type      ResultType
	Source    string
	Value     string
	Reference string
	Error     error
}

type ResultType int

const (
	Url ResultType = iota
	Error
)
