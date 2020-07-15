// +build !windows

package variables

const (
	ContainerBaseImage = "ubuntu:bionic"
	DockerfileName     = "Dockerfile"
	VolumeHelperImage  = "busybox"
	DummyCommand       = "true"
)

var DockerSocketMount = []string{"--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock"}
