// SPDX-FileCopyrightText: Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

func TestGenerateReferenceIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		name     string
		input    string
		expected IdentifiersBundle
		mustErr  bool
	}{
		{
			name:  "multi arch index",
			input: "alpine@sha256:eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/alpine@sha256%3Aeece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978?repository_url=index.docker.io%2Flibrary%2Falpine",
						"pkg:oci/alpine@sha256%3Aeece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978?arch=amd64&os=linux&repository_url=index.docker.io%2Flibrary%2Falpine",
						"pkg:oci/alpine@sha256%3A48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86?repository_url=index.docker.io%2Flibrary%2Falpine",
						"pkg:oci/alpine@sha256%3A48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86?arch=amd64&os=linux&repository_url=index.docker.io%2Flibrary%2Falpine",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"eece025e432126ce23f223450a0326fbebde39cdf496a85d8c016293fc851978",
						"48d9183eb12a05c99bcc0bf44a003607b8e941e1d4f41f9ad12bdcc4b5672f86",
					},
				},
			},
			mustErr: false,
		},
		{
			name:  "single arch image",
			input: "cgr.dev/chainguard/curl@sha256:3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/curl@sha256%3A3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8?repository_url=cgr.dev%2Fchainguard%2Fcurl",
						"pkg:oci/curl@sha256%3A3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8?arch=amd64&os=linux&repository_url=cgr.dev%2Fchainguard%2Fcurl",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"3b987bc327e8aa8e7db26822e0552d927d25392ccb4d3b9d30b5390b485520d8",
					},
				},
			},
			mustErr: false,
		},
		{
			name:  "tagged reference",
			input: "localhost:5000/scanner-test:unfixed-vulnerabilities-wolfi",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/scanner-test@sha256%3Aa0acdc09bf31ac45076a5850d0564ee144a9c8483f89eb869dc6ddd6218629c9?repository_url=localhost%3A5000%2Fscanner-test",
						"pkg:oci/scanner-test@sha256%3Aa0acdc09bf31ac45076a5850d0564ee144a9c8483f89eb869dc6ddd6218629c9?arch=amd64&os=linux&repository_url=localhost%3A5000%2Fscanner-test&tag=unfixed-vulnerabilities-wolfi",
						"pkg:oci/scanner-test@sha256%3A86e3ee69ede5f56514972d16fcfcfafbb54a65d2349c6f8419670bf7993d8583?repository_url=localhost%3A5000%2Fscanner-test",
						"pkg:oci/scanner-test@sha256%3A86e3ee69ede5f56514972d16fcfcfafbb54a65d2349c6f8419670bf7993d8583?arch=amd64&os=linux&repository_url=localhost%3A5000%2Fscanner-test&tag=unfixed-vulnerabilities-wolfi",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"a0acdc09bf31ac45076a5850d0564ee144a9c8483f89eb869dc6ddd6218629c9",
						"86e3ee69ede5f56514972d16fcfcfafbb54a65d2349c6f8419670bf7993d8583",
					},
				},
			},
			mustErr: false,
		},
		{
			name:    "invalid reference",
			input:   "invalid reference",
			mustErr: true,
		},
		{
			name:  "alpine-blank",
			input: "alpine@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expected: IdentifiersBundle{
				Identifiers: map[vex.IdentifierType][]string{
					vex.PURL: {
						"pkg:oci/alpine@sha256%3Affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff?repository_url=index.docker.io%2Flibrary%2Falpine",
						"pkg:oci/alpine@sha256%3Affffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff?arch=amd64&os=linux&repository_url=index.docker.io%2Flibrary%2Falpine",
					},
				},
				Hashes: map[vex.Algorithm][]vex.Hash{
					vex.SHA256: {
						"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
					},
				},
			},
			mustErr: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := GenerateReferenceIdentifiers(tc.input, "linux", "amd64")
			if tc.mustErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expected, res)
		})
	}
}

func TestPurlToReferenceString(t *testing.T) {
	for n, tc := range []struct {
		name              string
		testInput         string
		expectedReference string
		options           []RefConverterOptions
		mustError         bool
	}{
		{
			"normal",
			"pkg:oci/curl@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			"curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			[]RefConverterOptions{},
			false,
		},
		{
			"normal-with-repo",
			"pkg:oci/curl@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?repository_url=cgr.dev/chainguard/curl",
			"cgr.dev/chainguard/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			[]RefConverterOptions{},
			false,
		},
		{
			"latest",
			"pkg:oci/debian:latest",
			"debian:latest",
			[]RefConverterOptions{},
			false,
		},
		{
			"tag-and-digest",
			"pkg:oci/debian@sha256%3A47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?tag=latest",
			"debian@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			[]RefConverterOptions{},
			false,
		},
		{
			"non-oci",
			"pkg:apk/wolfi/ca-certificates-bundle@20230506-r0?arch=x86_64",
			"",
			[]RefConverterOptions{},
			true,
		},
		{
			"invalid",
			"Hello !",
			"",
			[]RefConverterOptions{},
			true,
		},
		{
			"repo-in-opts",
			"pkg:oci/debian:latest",
			"cgr.dev/debian:latest",
			[]RefConverterOptions{
				WithDefaultRepository("cgr.dev/"),
			},
			false,
		},
		{
			"repo-override",
			"pkg:oci/pause:latest?repository_url=k8s.gcr.io/pause",
			"registry.k8s.io/release/pause:latest",
			[]RefConverterOptions{
				WithOverrideRepository("registry.k8s.io/release/"),
			},
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref, err := PurlToReferenceString(tc.testInput, tc.options...)
			if tc.mustError {
				require.Error(t, err, n)
				return
			}
			require.Equal(t, tc.expectedReference, ref)
		})
	}
}
