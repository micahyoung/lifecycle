package variables

type VariableHelper struct {
	OS string
}

func (h *VariableHelper) DummyCommand() []string {
	if h.OS == "windows" {
		return []string{"cmd", "/c", "exit 0"}
	}
	return []string{"true"}
}

func (h *VariableHelper) DockerSocketMount() []string {
	if h.OS == "windows" {
		return []string{
			"--mount", `type=npipe,source=\\.\pipe\docker_engine,target=\\.\pipe\docker_engine`,
			"--user", "ContainerAdministrator",
		}
	}
	return []string{
		"--mount", "type=bind,source=/var/run/docker.sock,target=/var/run/docker.sock",
		"--user", "0",
	}
}

func (h *VariableHelper) ContainerBaseImage() string {
	if h.OS == "windows" {
		return "mcr.microsoft.com/windows/nanoserver:1809"
	}
	return "ubuntu:bionic"
}

func (h *VariableHelper) VolumeHelperImage() string {
	if h.OS == "windows" {
		return "mcr.microsoft.com/windows/nanoserver:1809"
	}
	return "busybox"
}

func (h *VariableHelper) CtrPath(unixPath string) string {
	if h.OS == "windows" {
		return "c:" + unixPath
	}
	return unixPath
}

func (h *VariableHelper) Dockerfilename() string {
	if h.OS == "windows" {
		return "Dockerfile.windows"
	}
	return "Dockerfile"
}
