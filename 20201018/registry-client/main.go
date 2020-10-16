package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/docker/distribution/registry/client"
	"github.com/docker/distribution/registry/client/auth"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/docker/distribution/registry/client/transport"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"transwarp.io/hunter/pkg/model"
	"transwarp.io/hunter/pkg/scanner"
	"transwarp.io/hunter/pkg/scheduler"
	"transwarp.io/hunter/pkg/utils"
)

const (
	HttpDenyRedirect = "deny redirect"
)

var (
	repositoryName = flag.String("repository", "", "Harbor repository")
	tag = flag.String("tag", "", "Docker image tag")
	registryURL = flag.String("registry_url", "", "Registry URL")
	username = flag.String("username", "", "Harbor username")
	password = flag.String("password", "", "Harbor password")
	insecureSkipVerify = flag.Bool("insecure_skip_verify", false, "Skip verify registry cert")
	reportPath = flag.String("report_path", ".", "Report Path")
	schedulerURL = flag.String("scheduler_url", "", "Scheduler URL")
	scanFS = flag.Bool("scan_fs", false, "scan host filesystem")
)

type credentialStore struct {
	username      string
	password      string
	refreshTokens map[string]string
}

func (cs *credentialStore) Basic(*url.URL) (string, string) {
	return cs.username, cs.password
}

func (cs *credentialStore) RefreshToken(_ *url.URL, service string) string {
	return cs.refreshTokens[service]
}

func (cs *credentialStore) SetRefreshToken(_ *url.URL, service string, token string) {
	if cs.refreshTokens != nil {
		cs.refreshTokens[service] = token
	}
}

type repository struct {
	 name string
}

func (r *repository) String() string {
	return r.name
}

func (r *repository) Name() string {
	return r.name
}

type scanMeta struct {
	repo string
	digest string
	tag string
	info interface{}
	jobID string
	scanner *scanner.Client
}

type RegistryScanner struct {
	url       *url.URL
	transport http.RoundTripper
	creds *credentialStore
	manager challenge.Manager
	scheduler scheduler.Client
	scanners []scanner.Client
	currentScannerIdx int
	metas []scanMeta
}

func (rs *RegistryScanner) getNextScanner() *scanner.Client {
	if rs.scanners == nil {
		return nil
	}
	rs.currentScannerIdx = (rs.currentScannerIdx + 1) % len(rs.scanners)
	return &rs.scanners[rs.currentScannerIdx]
}

func (rs *RegistryScanner) parseRegistry() error {
	options := auth.TokenHandlerOptions{
		Transport: rs.transport,
		Credentials: rs.creds,
		Scopes: []auth.Scope{
			auth.RegistryScope{
				Name:    "catalog",
				Actions: []string{"*"},
			},
		},
	}
	authTransport := transport.NewTransport(rs.transport,
		auth.NewAuthorizer(rs.manager, auth.NewBasicHandler(rs.creds),auth.NewTokenHandlerWithOptions(options)))

	reg, err := client.NewRegistry(rs.url.String(), authTransport)
	if err != nil {
		return err
	}

	last := ""
	for {
		repos := make([]string, 128)
		count, err := reg.Repositories(context.Background(), repos, last)
		if err != nil && err != io.EOF {
			return err
		}
		for _, repo := range repos {
			if err = rs.parseRepository(repo, ""); err != nil {
				return err
			}
		}
		if err == io.EOF {
			return nil
		}
		last = repos[count - 1]
	}
}

func (rs *RegistryScanner) parseRepository(repo, tag string) error {
	options := auth.TokenHandlerOptions{
		Transport: rs.transport,
		Credentials: rs.creds,
		Scopes: []auth.Scope{
			auth.RepositoryScope{
				Repository: repo,
				Class:      "image",
				Actions:    []string{"pull"},
			},
		},
	}
	authTransport := transport.NewTransport(rs.transport,
		auth.NewAuthorizer(rs.manager, auth.NewBasicHandler(rs.creds),auth.NewTokenHandlerWithOptions(options)))

	repository, err := client.NewRepository(&repository{repo}, rs.url.String(), authTransport)
	if err != nil {
		return err
	}

	tagService := repository.Tags(context.Background())
	tags, err := tagService.All(context.Background())
	if err != nil {
		return err
	}

	if tag == "" {
		for _, tag := range tags {
			desc, err := tagService.Get(context.Background(), tag)
			if err != nil {
				return err
			}
			err = rs.request(nil, repo, "", tag, desc)
			if err != nil {
				log.Warn(err)
			}
		}
	} else {
		desc, err := tagService.Get(context.Background(), tag)
		if err != nil {
			return err
		}
		err = rs.request(nil, repo, "", tag, desc)
		if err != nil {
			log.Warn(err)
		}
	}

	return nil
}

func (rs *RegistryScanner) parseHostImages(repo, tag string) error {
	for i, s := range rs.scanners {
		images, err := s.HostImages()
		if err != nil {
			return err
		}
		for _, image := range images {
			if tag == "" {
				if image.RepoDigests != nil {
					for _, repoDigest := range image.RepoDigests {
						idx := strings.LastIndex(repoDigest, "@")
						if idx == -1 {
							return fmt.Errorf("cannot split repo digest %s", repoDigest)
						}
						r := repoDigest[:idx]
						d := repoDigest[idx + 1:]

						if repo != "" && r != repo {
							continue
						}
						if err = rs.request(&rs.scanners[i], r, d, "", image); err != nil {
							log.Warn(err)
						}
					}
				} else {
					for _, repoTag := range image.RepoTags {
						idx := strings.LastIndex(repoTag, ":")
						if idx == -1 {
							return fmt.Errorf("cannot split repo tag %s", repoTag)
						}
						r := repoTag[:idx]
						t := repoTag[idx + 1:]

						if repo != "" && r!= repo {
							continue
						}
						if err = rs.request(&rs.scanners[i], r, "", t, image); err != nil {
							log.Warn(err)
						}
					}
				}
			} else {
				for _, repoTag := range image.RepoTags {
					idx := strings.LastIndex(repoTag, ":")
					if idx == -1 {
						return fmt.Errorf("cannot split repo tag %s", repoTag)
					}
					r := repoTag[:idx]
					t := repoTag[idx + 1:]

					if repo != "" && r != repo {
						continue
					}
					if tag != "" && t != tag {
						continue
					}
					if err = rs.request(&rs.scanners[i], r, "", t, image); err != nil {
						log.Warn(err)
					}
				}
			}
		}
	}

	return nil
}

func (rs *RegistryScanner) request(s *scanner.Client, repo, digest, tag string, info interface{}) error {
	if s == nil {
		s = rs.getNextScanner()
		if s == nil {
			return fmt.Errorf("no scanners to scan")
		}
	}

	author := ""
	if rs.creds.username != "" && rs.creds.password != "" {
		author = "Basic " + base64.StdEncoding.EncodeToString([]byte(rs.creds.username + ":" + rs.creds.password))
	}

	scanResp ,err := s.Scan(model.ScanRequest{
		Registry: model.Registry{
			URL: rs.url.String(),
			Authorization: author,
		},
		Artifact: model.Artifact{
			Repository: repo,
			Digest: digest,
			Tag: tag,
		},
	})
	if err != nil {
		return err
	}
	rs.metas = append(rs.metas, scanMeta{
		repo: repo,
		digest: digest,
		tag: tag,
		info: info,
		jobID: scanResp.ID,
		scanner: s,
	})

	if digest != "" {
		log.Infof("request scan %s@%s to scanner %s", repo, digest, s.URL)
	} else if tag != "" {
		log.Infof("request scan %s:%s to scanner %s", repo, tag, s.URL)
	} else {
		log.Infof("request scan host filesystem to scanner %s", s.URL)
	}

	return nil
}

func (rs *RegistryScanner) getReports(reportPath string) error {
	for _, meta := range rs.metas {
		if meta.digest != "" {
			log.Infof("request %s@%s report from scanner %s with id %s", meta.repo, meta.digest, meta.scanner.URL, meta.jobID)
		} else if meta.tag != "" {
			log.Infof("request %s:%s report from scanner %s with id %s", meta.repo, meta.tag, meta.scanner.URL, meta.jobID)
		} else {
			log.Infof("request host filesystem report from scanner %s with id %s", meta.scanner.URL, meta.jobID)
		}
		for {
			time.Sleep(5 * time.Second)
			scanReport, err := meta.scanner.ScanReport(meta.jobID)
			if err != nil {
				if !strings.HasSuffix(err.Error(), HttpDenyRedirect) {
					log.Warn(err)
					break
				}
			} else {
				b, err := json.Marshal(scanReport)
				if err != nil {
					return err
				}
				rp := reportPath
				if rs.url.Host != "" {
					rp += "/" + rs.url.Host
				} else {
					u, err := url.Parse(meta.scanner.URL)
					if err != nil {
						return err
					}
					rp += "/" + u.Hostname()
				}
				if meta.digest != "" {
					rp += "/" + meta.repo + "@" + meta.digest + ".json"
				} else if meta.tag != "" {
					rp += "/" + meta.repo + ":" + meta.tag + ".json"
				} else {
					rp += "/filesystem.json"
				}
				dir := path.Dir(rp)
				if err = os.MkdirAll(dir, 0755); err != nil {
					return err
				}
				if err = ioutil.WriteFile(rp, b, 0644); err != nil {
					return err
				}
				if meta.digest != "" {
					log.Infof("write %s@%s report to %s", meta.repo, meta.digest, rp)
				} else if meta.tag != "" {
					log.Infof("write %s:%s report to %s", meta.repo, meta.tag, rp)
				} else {
					log.Infof("write host filesystem report to %s", rp)
				}
				break
			}
		}
	}

	return nil
}

func (rs *RegistryScanner) ping(versionHeader string) ([]auth.APIVersion, error) {
	c := http.Client{Transport: rs.transport}
	resp, err := c.Get(rs.url.String() + "/v2")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err = resp.Body.Close(); err != nil {
			log.Error(err)
		}
	}()

	err = rs.manager.AddResponse(resp)
	if err != nil {
		return nil, err
	}

	return auth.APIVersions(resp, versionHeader), err
}

func main() {
	var scannerURLs []string
	flag.Var(utils.NewSliceValue([]string{}, &scannerURLs), "scanner_urls", "Scanner URLs")
	flag.Parse()

	var scannerClients []scanner.Client
	for _, scannerURL := range scannerURLs {
		scannerClients = append(scannerClients, scanner.Client{
			Client: &http.Client{
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return errors.New(HttpDenyRedirect)
				}},
			URL: scannerURL,
		})
	}

	regURL, err := url.Parse(*registryURL)
	if err != nil {
		log.Fatal(err)
	}

	rs := RegistryScanner{
		url: regURL,
		transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: *insecureSkipVerify,
			},
		},
		creds:  &credentialStore{
			username: *username,
			password: *password,
			refreshTokens: make(map[string]string),
		},
		manager: challenge.NewSimpleManager(),
		scheduler: scheduler.Client{
			Client: http.DefaultClient,
			URL:    *schedulerURL,
		},
		scanners: scannerClients,
		currentScannerIdx: -1,
	}

	if *scanFS {
		// ensure empty url
		rs.url = &url.URL{}
		for i := range rs.scanners {
			if err = rs.request(&rs.scanners[i], "", "", "", nil); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		if *registryURL == "" {
			if err = rs.parseHostImages(*repositoryName, *tag); err != nil {
				log.Fatal(err)
			}
		} else {
			_, err = rs.ping("Docker-Distribution-Api-Version")
			if err != nil {
				log.Fatal(err)
			}

			if *repositoryName == "" {
				err = rs.parseRegistry()
			} else {
				err = rs.parseRepository(*repositoryName, *tag)
			}
			if err != nil {
				log.Fatal(err)
			}
		}
	}

	if err = rs.getReports(*reportPath); err != nil {
		log.Fatal(err)
	}
}
