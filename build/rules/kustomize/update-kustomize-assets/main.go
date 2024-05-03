package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/bazelbuild/buildtools/build"
	"github.com/google/go-github/v41/github"
	"github.com/spf13/pflag"
	"go.f110.dev/xerrors"
)

const (
	KustomizeRepositoryOwner = "kubernetes-sigs"
	KustomizeRepositoryName  = "kustomize"
)

type release struct {
	Version string
	Assets  []*asset
}

type asset struct {
	OS     string
	Arch   string
	URL    string
	SHA256 string
}

func getRelease(ver string) (*release, error) {
	gClient := github.NewClient(nil)
	rel, _, err := gClient.Repositories.GetReleaseByTag(
		context.TODO(),
		KustomizeRepositoryOwner,
		KustomizeRepositoryName,
		fmt.Sprintf("kustomize/%s", ver),
	)
	if err != nil {
		return nil, err
	}

	assets := make(map[string]*asset)
	checksums := make(map[string]string)
	for _, v := range rel.Assets {
		if v.GetName() == "checksums.txt" {
			checksums, err = getChecksum(context.TODO(), v.GetBrowserDownloadURL())
			if err != nil {
				return nil, err
			}
			continue
		}
		s := strings.Split(v.GetName(), "_")
		if s[3] != "amd64.tar.gz" && s[3] != "arm64.tar.gz" {
			continue
		}
		a := strings.Split(s[3], ".")
		arch := a[0]
		assets[v.GetName()] = &asset{
			OS:   s[2],
			Arch: arch,
			URL:  v.GetBrowserDownloadURL(),
		}
	}
	newRelease := &release{Version: ver, Assets: make([]*asset, 0)}
	for _, v := range assets {
		u, err := url.Parse(v.URL)
		if err != nil {
			return nil, err
		}
		filename := filepath.Base(u.Path)
		if checksum, ok := checksums[filename]; !ok {
			return nil, xerrors.Newf("unknown filename: %s", filename)
		} else {
			v.SHA256 = checksum
		}

		newRelease.Assets = append(newRelease.Assets, v)
	}

	return newRelease, nil
}

func getChecksum(ctx context.Context, url string) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	contents, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	sums := make(map[string]string)
	s := bufio.NewScanner(bytes.NewReader(contents))
	for s.Scan() {
		line := s.Text()
		s := strings.Split(line, "  ")
		sums[s[1]] = s[0]
	}

	return sums, nil
}

func updateKustomizeAssets(args []string) error {
	assetsFile := ""
	version := ""
	overwrite := false
	fs := pflag.NewFlagSet("update-kustomize-assets", pflag.ContinueOnError)
	fs.StringVar(&assetsFile, "assets-file", "", "File path of assets.bzl")
	fs.StringVar(&version, "version", "", "Version of kustomize")
	fs.BoolVar(&overwrite, "overwrite", false, "Overwrite")
	if err := fs.Parse(args); err != nil {
		return err
	}

	buf, err := os.ReadFile(assetsFile)
	if err != nil {
		return err
	}
	f, err := build.Parse(filepath.Base(assetsFile), buf)
	if err != nil {
		return err
	}
	if len(f.Stmt) != 1 {
		return xerrors.New("the file has to include dict assign only")
	}
	a, ok := f.Stmt[0].(*build.AssignExpr)
	if !ok {
		return xerrors.Newf("statement is not assign: %s", reflect.TypeOf(f.Stmt[0]).String())
	}
	dict, ok := a.RHS.(*build.DictExpr)
	if !ok {
		return xerrors.Newf("RHS is not dict: %s", reflect.TypeOf(a.RHS).String())
	}
	exists := make(map[string]*build.KeyValueExpr)
	for _, v := range dict.List {
		key, ok := v.Key.(*build.StringExpr)
		if !ok {
			continue
		}
		exists[key.Value] = v
	}
	if _, ok := exists[version]; ok {
		log.Printf("%s is already exists", version)
		return nil
	}

	if version != "" {
		rel, err := getRelease(version)
		if err != nil {
			return err
		}
		dict.List = append(dict.List, releaseToKeyValueExpr(rel))
		sort.Slice(dict.List, func(i, j int) bool {
			left := semver.MustParse(dict.List[i].Key.(*build.StringExpr).Value)
			right := semver.MustParse(dict.List[j].Key.(*build.StringExpr).Value)
			return left.LessThan(right)
		})
	}
	out := build.FormatString(f)
	fmt.Print(out)

	if overwrite {
		if err := os.WriteFile(assetsFile, []byte(out), 0644); err != nil {
			return err
		}
	}

	return nil
}

func releaseToKeyValueExpr(release *release) *build.KeyValueExpr {
	sort.Slice(release.Assets, func(i, j int) bool {
		return release.Assets[i].OS < release.Assets[j].OS
	})
	assets := make(map[string][]*asset)
	var osNames []string
	for _, v := range release.Assets {
		if _, ok := assets[v.OS]; !ok {
			osNames = append(osNames, v.OS)
		}
		assets[v.OS] = append(assets[v.OS], v)
	}
	sort.Strings(osNames)

	files := make([]*build.KeyValueExpr, 0)
	for _, osName := range osNames {
		v := assets[osName]
		sort.Slice(v, func(i, j int) bool {
			return v[i].Arch < v[j].Arch
		})

		osFiles := &build.DictExpr{}
		for _, a := range v {
			osFiles.List = append(osFiles.List, &build.KeyValueExpr{
				Key: &build.StringExpr{Value: a.Arch},
				Value: &build.TupleExpr{
					List: []build.Expr{
						&build.StringExpr{Value: a.URL},
						&build.StringExpr{Value: a.SHA256},
					},
				},
			})
		}

		files = append(files, &build.KeyValueExpr{
			Key:   &build.StringExpr{Value: osName},
			Value: osFiles,
		})
	}

	kv := &build.KeyValueExpr{
		Key: &build.StringExpr{Value: release.Version},
		Value: &build.DictExpr{
			List: files,
		},
	}

	return kv
}

func main() {
	if err := updateKustomizeAssets(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
