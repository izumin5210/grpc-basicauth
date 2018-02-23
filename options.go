package grpcbasicauth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"

	"github.com/grpc-ecosystem/go-grpc-middleware/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// BasicAuthOptions contains configurations of basic authentication on gRPC server.
type BasicAuthOptions struct {
	username       string
	password       string
	skippedMethods map[string]struct{}
	enc            *base64.Encoding
}

// BasicAuthOption configures basic authentication on gRPC server.
type BasicAuthOption func(*BasicAuthOptions)

// WithSkippedMethods returns a BasicAuthOption which appends method name to be skipped basic authentication.
func WithSkippedMethods(fullMethodNames ...string) BasicAuthOption {
	return func(o *BasicAuthOptions) {
		for _, mth := range fullMethodNames {
			o.skippedMethods[mth] = struct{}{}
		}
	}
}

func createBasicAuthOptions(username, password string, opts []BasicAuthOption) *BasicAuthOptions {
	o := &BasicAuthOptions{
		username:       username,
		password:       password,
		skippedMethods: make(map[string]struct{}),
		enc:            base64.StdEncoding,
	}
	for _, f := range opts {
		f(o)
	}
	return o
}

func (o *BasicAuthOptions) shouldAuth(fullMethodName string) bool {
	_, ok := o.skippedMethods[fullMethodName]
	return !ok
}

func (o *BasicAuthOptions) endocdedCredential() []byte {
	src := []byte(o.username + ":" + o.password)
	dest := make([]byte, o.enc.EncodedLen(len(src)))
	o.enc.Encode(dest, src)
	return dest
}

func (o *BasicAuthOptions) createAttachMDFunc() func(context.Context) context.Context {
	if o.username == "" && o.password == "" {
		return func(c context.Context) context.Context {
			return c
		}
	}

	md := metadata.New(map[string]string{
		"authorization": "basic " + string(o.endocdedCredential()),
	})

	return func(c context.Context) context.Context {
		return metadata.NewOutgoingContext(c, md)
	}
}

func (o *BasicAuthOptions) createAuthFunc() grpc_auth.AuthFunc {
	if o.username == "" && o.password == "" {
		return func(c context.Context) (context.Context, error) {
			return c, nil
		}
	}

	want := o.endocdedCredential()

	return func(c context.Context) (context.Context, error) {
		got, err := grpc_auth.AuthFromMD(c, "basic")

		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "failed to authentication: %v", err)
		}
		if subtle.ConstantTimeCompare([]byte(got), want) != 1 {
			return nil, status.Error(codes.Unauthenticated, "username or passward is invalid")
		}

		return c, nil
	}
}
