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
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/go-connections/nat"
	"github.com/pkg/errors"
	"golang.org/x/crypto/bcrypt"
)

// TODO: remove this file and PR changes back to imgutil

type DockerRegistry struct {
	HostIP          string
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

	// Get port
	inspect, err := DockerCli(t).ContainerInspect(ctx, ctr.ID)
	AssertNil(t, err)

	r.HostIP = "localhost"
	r.Port = inspect.NetworkSettings.Ports["5000/tcp"][0].HostPort
	if strings.Contains(DockerCli(t).DaemonHost(), "pipe") { // Docker in Docker
		r.HostIP = inspect.NetworkSettings.Networks["nat"].IPAddress // Only works on Windows, but that's the only time we currently need Docker in Docker
		r.Port = "5000"
	}

	var authHeaders map[string]string
	if r.username != "" {
		// Write Docker config and configure auth headers
		writeDockerConfig(t, r.DockerDirectory, r.HostIP, r.Port, r.encodedAuth())

		configContents, _ := ioutil.ReadFile(filepath.Join(r.DockerDirectory, "config.json"))
		fmt.Println("config contents:", string(configContents))

		authHeaders = map[string]string{"Authorization": "Basic " + r.encodedAuth()}
	}

	// Wait for registry to be ready
	Eventually(t, func() bool {
		txt, err := HTTPGetE(fmt.Sprintf("http://%s:%s/v2/_catalog", r.HostIP, r.Port), authHeaders)
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

func (r *DockerRegistry) RepoName(name string) string {
	return r.HostIP + ":" + r.Port + "/" + name
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
