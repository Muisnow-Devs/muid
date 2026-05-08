package identity

type FlowStep = string

const (
	AuthStepStart     FlowStep = "start"
	AuthStepContinue  FlowStep = "continue"
	AuthStepCompleted FlowStep = "completed"
)
