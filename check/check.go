package check

type Check interface {
	Target() string
	SetTarget(string) error
	Run() error
	Stop()
	Statistics() *Statistics
}
