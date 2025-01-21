package netcontroller

type NetController interface {
	FindNodeNetwork(nodeName string, masterIf string) (string, bool)
	Watch()
}
