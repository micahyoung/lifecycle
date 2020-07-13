package testhelpers

import (
	"archive/tar"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

type DockerRegistry struct {
	Host            string
	Port            string
	Name            string
	DockerDirectory string
	username        string
	password        string
}

var registryImageNames = map[string]string{
	"linux":   "registry:2",
	"windows": "stefanscherer/registry-windows:2.6.2",
}

func NewDockerRegistry() *DockerRegistry {
	return &DockerRegistry{
		Name: "test-registry-" + RandString(10),
	}
}

func NewDockerRegistryWithAuth(dockerConfigDir string) *DockerRegistry {
	return &DockerRegistry{
		Name:            "test-registry-" + RandString(10),
		username:        RandString(10),
		password:        RandString(10),
		DockerDirectory: dockerConfigDir,
	}
}

func (r *DockerRegistry) Start(t *testing.T) {
	t.Log("run registry")
	t.Helper()

	ctx := context.Background()
	daemonInfo, err := DockerCli(t).Info(ctx)
	AssertNil(t, err)

	registryImageName := registryImageNames[daemonInfo.OSType]
	AssertNil(t, PullImage(DockerCli(t), registryImageName))

	var htpasswdTar io.ReadCloser
	registryEnv := []string{"REGISTRY_STORAGE_DELETE_ENABLED=true"}
	if r.username != "" {
		// Create htpasswdTar and configure registry env
		tempDir, err := ioutil.TempDir("", "test.registry")
		AssertNil(t, err)
		defer os.RemoveAll(tempDir)

		htpasswdTar = generateHtpasswd(t, tempDir, r.username, r.password)
		defer htpasswdTar.Close()

		otherEnvs := []string{
			"REGISTRY_AUTH=htpasswd",
			"REGISTRY_AUTH_HTPASSWD_REALM=Registry Realm",
			"REGISTRY_AUTH_HTPASSWD_PATH=/registry_test_htpasswd",
		}
		registryEnv = append(registryEnv, otherEnvs...)
	}

	// Create container
	ctr, err := DockerCli(t).ContainerCreate(ctx, &container.Config{
		Image: registryImageName,
		Env:   registryEnv,
	}, &container.HostConfig{
		AutoRemove: true,
		PortBindings: nat.PortMap{
			"5000/tcp": []nat.PortBinding{{}},
		},
	}, nil, r.Name)
	AssertNil(t, err)

	if r.username != "" {
		// Copy htpasswdTar to container
		AssertNil(t, DockerCli(t).CopyToContainer(ctx, ctr.ID, "/", htpasswdTar, types.CopyToContainerOptions{}))
	}

	// Start container
	AssertNil(t, DockerCli(t).ContainerStart(ctx, ctr.ID, types.ContainerStartOptions{}))

	rc, stat, err := DockerCli(t).CopyFromContainer(ctx, ctr.ID, "/registry_test_htpasswd")
	AssertNil(t, err)
	defer rc.Close()
	p := make([]byte, stat.Size)
	_, err = rc.Read(p)
	AssertNil(t, err)
	fmt.Println("from container:", string(p))
	tempFile, err := ioutil.TempFile("", "")
	AssertNil(t, err)
	ioutil.WriteFile(tempFile.Name(), p, 0755)
	fmt.Println("tempfile:", tempFile.Name())

	//cmd := exec.Command("docker", "exec", ctr.ID, "dir", "C:\\")
	//output, err := cmd.CombinedOutput()
	//fmt.Println("output:", string(output))
	//AssertNil(t, err)

	// Get port
	inspect, err := DockerCli(t).ContainerInspect(ctx, ctr.ID)
	AssertNil(t, err)

	fmt.Printf("Network settings: %+#v\n", inspect.NetworkSettings)
	fmt.Printf("Networks: %+#v\n", inspect.NetworkSettings.Networks["bridge"])
	fmt.Println("Hostname path:", inspect.HostnamePath)
	r.Port = "5000"
	fmt.Println("docker host:", DockerCli(t).DaemonHost())
	r.Host = inspect.NetworkSettings.Networks["nat"].IPAddress
	fmt.Println("registry host:", r.Host)

	var authHeaders map[string]string
	if r.username != "" {
		// Write Docker config and configure auth headers
		writeDockerConfig(t, r.DockerDirectory, r.Host, r.Port, r.encodedAuth())

		configContents, _ := ioutil.ReadFile(filepath.Join(r.DockerDirectory, "config.json"))
		fmt.Println("config contents:", string(configContents))

		authHeaders = map[string]string{"Authorization": "Basic " + r.encodedAuth()}
	}

	fmt.Println("auth headers:", authHeaders)

	// Wait for registry to be ready
	Eventually(t, func() bool {
		txt, err := HTTPGetE(fmt.Sprintf("http://%s:%s/v2/_catalog", r.Host, r.Port), authHeaders)
		if err != nil {
			fmt.Println("registry error:", err.Error())
		}
		return err == nil && txt != ""
	}, 100*time.Millisecond, 10*time.Second)
}

func (r *DockerRegistry) Stop(t *testing.T) {
	t.Log("stop registry")
	t.Helper()
	if r.Name != "" {
		DockerCli(t).ContainerKill(context.Background(), r.Name, "SIGKILL")
		DockerCli(t).ContainerRemove(context.TODO(), r.Name, types.ContainerRemoveOptions{Force: true})
	}
}

//func registryHost(t *testing.T) string {
//	host := "localhost"
//	if dockerHost := DockerCli(t).DaemonHost(); dockerHost != "" {
//		//u, err := url.Parse(dockerHost)
//		//if err != nil {
//		//	panic("unable to parse DOCKER_HOST: " + err.Error())
//		//}
//		host = dockerHost
//	}
//
//	return host
//}

func (r *DockerRegistry) RepoName(name string) string {
	return r.Host + ":" + r.Port + "/" + name
}

func (r *DockerRegistry) EncodedLabeledAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf(`{"username":"%s","password":"%s"}`, r.username, r.password)))
}

func (r *DockerRegistry) encodedAuth() string {
	return base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", r.username, r.password)))
}

func generateHtpasswd(t *testing.T, tempDir string, username string, password string) io.ReadCloser {
	// https://docs.docker.com/registry/deploying/#restricting-access
	// HTPASSWD format: https://github.com/foomo/htpasswd/blob/e3a90e78da9cff06a83a78861847aa9092cbebdd/hashing.go#L23
	passwordBytes, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	return CreateSingleFileTarReader("/registry_test_htpasswd", username+":"+string(passwordBytes))
}

func writeDockerConfig(t *testing.T, configDir, host, port, auth string) {
	AssertNil(t, ioutil.WriteFile(
		filepath.Join(configDir, "config.json"),
		[]byte(fmt.Sprintf(`{
			  "auths": {
			    "%s:%s": {
			      "auth": "%s"
			    }
			  }
			}
			`, host, port, auth)),
		0666,
	))
}

func CreateSingleFileTarReader(path, txt string) io.ReadCloser {
	pr, pw := io.Pipe()

	go func() {
		var err error
		defer func() {
			pw.CloseWithError(err)
		}()

		tw := tar.NewWriter(pw)
		defer tw.Close()

		err = writeTarSingleFileLinux(tw, path, txt) // Use the Linux writer, as this isn't a layer tar.
	}()

	return pr
}

func writeTarSingleFileLinux(tw *tar.Writer, layerPath, txt string) error {
	if err := tw.WriteHeader(&tar.Header{Name: layerPath, Size: int64(len(txt)), Mode: 0644}); err != nil {
		return err
	}

	if _, err := tw.Write([]byte(txt)); err != nil {
		return err
	}

	return nil
}

func HTTPGetE(url string, headers map[string]string) (string, error) {
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", errors.Wrap(err, "making new request")
	}

	for key, val := range headers {
		request.Header.Set(key, val)
	}

	resp, err := http.DefaultClient.Do(request)
	if err != nil {
		return "", errors.Wrap(err, "doing request")
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return "", fmt.Errorf("HTTP Status was bad: %s => %d", url, resp.StatusCode)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
