package variables

const (
	ContainerBaseImage = "mcr.microsoft.com/windows/nanoserver:1809"
	DockerfileName     = "Dockerfile.windows"
	VolumeHelperImage  = "mcr.microsoft.com/windows/nanoserver:1809"
	DummyCommand       = "dir"
)

var DockerSocketMount = []string{"--volume", "\\\\.\\pipe\\docker_engine:\\\\.\\pipe\\docker_engine"}
